export function createRequestHeaders(
	encryptedPayload: string,
	keys: { publicKey: string; privateKey: string },
	ttl: number,
) {
	return {
		"crypto-key": `p256ecdsa=${keys.publicKey}`,
		"content-encoding": "aesgcm",
		encryption: `keyid=p256dh;salt=${encryptedPayload}`,
		ttl: `${ttl}`,
	};
}
