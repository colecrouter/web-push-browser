import base64url from "base64url";

const encode = base64url.encode;

export async function encryptPayload(
	payload: string,
	sharedSecret: CryptoKey,
	salt: Uint8Array,
) {
	const encodedPayload = new TextEncoder().encode(payload);
	const encrypted = await crypto.subtle.encrypt(
		{
			name: "AES-GCM",
			iv: salt,
		},
		sharedSecret,
		encodedPayload,
	);
	return encode(encrypted);
}
