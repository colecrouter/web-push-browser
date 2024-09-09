import type { PushNotificationSubscription } from "../types.js";
import { toBase64Url } from "../utils/base64url.js";

/**
 * Generate the headers for a Web Push request.
 * @param publicVapidKey - The public VAPID key.
 * @param jwt - The signed JWT token.
 * @param encryptedPayload - The encrypted payload.
 * @param salt - The salt used to encrypt the payload.
 * @param localPublicKey - The public key used to encrypt the payload.
 * @param ttl - The time-to-live for the notification.
 * @returns The generated headers.
 */
export async function generateHeaders(
	publicVapidKey: CryptoKey,
	jwt: string,
	encryptedPayload: ArrayBuffer,
	salt: ArrayBuffer,
	localPublicKey: CryptoKey,
	ttl = 86400,
) {
	const exportedPubKey = await crypto.subtle.exportKey("raw", publicVapidKey);
	const encodedPubKey = toBase64Url(exportedPubKey);

	const exportedLocalPubKey = await crypto.subtle.exportKey(
		"raw",
		localPublicKey,
	);
	const encodedLocalPubKey = toBase64Url(exportedLocalPubKey);

	const headers = new Headers();
	headers.append("Authorization", `Bearer ${jwt}`);
	const cryptoKey = new URLSearchParams();
	cryptoKey.set("dh", encodedLocalPubKey);

	// On Microsoft Edge servers, this doesn't work, despite being documented in the spec
	// headers.append("Crypto-Key", `p256ecdsa=${encodedPubKey}`);
	// headers.append("Crypto-Key", `dh=${encodedLocalPubKey}`);

	// Also on Microsoft, the order matters, despite the spec saying it doesn't
	headers.append(
		"Crypto-Key",
		`p256ecdsa=${encodedPubKey};dh=${encodedLocalPubKey}`,
	);

	headers.append("Content-Encoding", "aesgcm");
	headers.append("Content-Type", "application/octet-stream");
	headers.append("Content-Length", encryptedPayload.byteLength.toString());
	headers.append("Encryption", `salt=${toBase64Url(salt)}`);
	headers.append("TTL", Math.floor(ttl).toString());

	return headers;
}
