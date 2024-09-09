export async function deriveSharedSecret(
	publicKey: CryptoKey,
	privateKey: CryptoKey,
): Promise<CryptoKey> {
	const sharedSecret = await crypto.subtle.deriveKey(
		{
			name: "ECDH",
			public: publicKey,
		},
		privateKey,
		{
			name: "AES-GCM",
			length: 256,
		},
		true,
		["encrypt", "decrypt"],
	);

	return sharedSecret;
}
