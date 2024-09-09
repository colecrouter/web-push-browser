import type { JWK } from "jose";
import base64url from "base64url";

const encode = base64url.encode;

export function base64UrlToUint8Array(base64Url: string): Uint8Array {
	const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
	const binaryString = atob(base64);
	const len = binaryString.length;
	const bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes;
}

function uint8ArrayToBase64Url(uint8Array: Uint8Array): string {
	const binaryString = String.fromCharCode.apply(null, uint8Array as any);
	const base64 = btoa(binaryString);
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function createRequestHeaders(
	encryptedPayload: string,
	publicJWK: JWK,
	salt: Uint8Array,
	ttl: number,
) {
	// Extract the x and y coordinates from the public JWK
	const x = base64UrlToUint8Array(publicJWK.x ?? "");
	const y = base64UrlToUint8Array(publicJWK.y ?? "");

	// Concatenate x and y coordinates
	const publicKeyUint8Array = new Uint8Array(x.length + y.length);
	publicKeyUint8Array.set(x);
	publicKeyUint8Array.set(y, x.length);

	// Convert the concatenated public key to base64url
	const publicKeyBase64 = uint8ArrayToBase64Url(publicKeyUint8Array);

	// Convert the salt to base64url
	const saltBase64 = uint8ArrayToBase64Url(salt);

	return {
		"crypto-key": `p256ecdsa=${publicKeyBase64}`,
		"content-encoding": "aesgcm",
		encryption: `keyid=p256dh;salt=${saltBase64}`,
        "authorization": "WebPush " +
		ttl: ttl.toString(),
	};
}
