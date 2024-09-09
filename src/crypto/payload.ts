import type { PushNotificationSubscription } from "../types.js";
import { fromBase64Url } from "../utils/base64url.js";

/**
 * Encrypt a plaintext payload using the keys provided by the PushSubscription.
 * @param payload - The plaintext payload to encrypt.
 * @param keys - The keys from the PushSubscription.
 */
export async function encryptPayload(
	payload: string,
	keys: PushNotificationSubscription["keys"],
) {
	const encoder = new TextEncoder();
	const salt = crypto.getRandomValues(new Uint8Array(16));

	if (!keys.p256dh || !keys.auth) {
		throw new Error("Missing p256dh or auth key");
	}

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
	const cekInfo = encoder.encode("Content-Encoding: aes128gcm");
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

	// Construct the header
	const header = new Uint8Array([
		...salt, // 16 bytes
		...new Uint8Array(4), // 4 bytes for record size (we'll fill this later)
		...serverPublicKeyBytes, // 65 bytes for public key
	]);

	// Construct the full message
	const message = new Uint8Array([
		...header,
		...new Uint8Array(encryptedPayload),
	]);

	// Now fill in the record size
	const recordSize = new Uint32Array([encryptedPayload.byteLength]);
	new Uint8Array(message.buffer, 16, 4).set(new Uint8Array(recordSize.buffer));
	const encrypted = message.buffer;
	const serverPublicKey = localKeyPair.publicKey;

	return { encrypted, salt, serverPublicKey };
}
