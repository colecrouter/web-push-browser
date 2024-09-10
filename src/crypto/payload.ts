import type { PushNotificationSubscription } from "../types.js";
import { fromBase64Url, toBase64Url } from "../utils/base64url.js";

type EncryptionOptions = {
	algorithm: "aesgcm" | "aes128gcm";
};

/**
 * Encrypt a plaintext payload using the keys provided by the PushSubscription.
 * @param payload - The plaintext payload to encrypt.
 * @param keys - The keys from the PushSubscription.
 * @param options - Options for encryption. Defaults to AES128GCM if not specified.
 */
export async function encryptPayload(
	payload: string,
	keys: PushNotificationSubscription["keys"],
	options: EncryptionOptions = { algorithm: "aes128gcm" },
) {
	const encoder = new TextEncoder();
	const salt = crypto.getRandomValues(new Uint8Array(16));

	// Get the p256dh and auth keys from the subscription
	const auth =
		typeof keys.auth === "string" ? fromBase64Url(keys.auth) : keys.auth;
	const p256dh =
		typeof keys.p256dh === "string" ? fromBase64Url(keys.p256dh) : keys.p256dh;

	// Generate a new ECDH key pair for this encryption
	const localKeyPair = await crypto.subtle.generateKey(
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		["deriveBits"],
	);

	// Import the client's public key
	const clientPublicKey = await crypto.subtle.importKey(
		"raw",
		p256dh,
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		[],
	);

	// Generate a shared secret
	const sharedSecret = await crypto.subtle.deriveBits(
		{ name: "ECDH", public: clientPublicKey },
		localKeyPair.privateKey,
		256,
	);

	// Create the PRK
	const prk = await crypto.subtle.importKey(
		"raw",
		await crypto.subtle.digest(
			"SHA-256",
			new Uint8Array([
				...new Uint8Array(auth),
				...new Uint8Array(sharedSecret),
			]),
		),
		{ name: "HKDF" },
		false,
		["deriveBits"],
	);

	// Derive the Content Encryption Key
	const cekInfo = encoder.encode(`Content-Encoding: ${options.algorithm}`);
	const cek = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: salt,
			info: cekInfo,
		},
		prk,
		128,
	);

	const iv = crypto.getRandomValues(new Uint8Array(12));

	// Encrypt the payload
	const encryptedPayload = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: iv },
		await crypto.subtle.importKey(
			"raw",
			new Uint8Array(cek),
			{ name: "AES-GCM" },
			false,
			["encrypt"],
		),
		encoder.encode(payload),
	);

	// Prepend the salt and server public key to the payload
	// Export the server's public key
	const serverPublicKeyBytes = new Uint8Array(
		await crypto.subtle.exportKey("raw", localKeyPair.publicKey),
	);

	let encrypted: ArrayBuffer;

	if (options.algorithm === "aes128gcm") {
		// AES128GCM header format:
		// Salt (16 bytes) || RS (4 bytes) || IdLen (1 byte) || PublicKey (65 bytes)
		const recordSize = 4096; // You can adjust this value
		const idLen = 65; // Length of the public key

		const header = new Uint8Array(16 + 4 + 1 + 65);
		header.set(salt, 0); // Correctly setting the salt here
		new DataView(header.buffer).setUint32(16, recordSize, false);
		header[20] = idLen;
		header.set(serverPublicKeyBytes, 21);

		encrypted = new Uint8Array([...header, ...new Uint8Array(encryptedPayload)])
			.buffer;
	} else {
		// For 'aesgcm', we don't include the header in the encrypted payload
		encrypted = encryptedPayload;
	}
	const localPublicKey = localKeyPair.publicKey;

	return { encrypted, salt, localPublicKey };
}
