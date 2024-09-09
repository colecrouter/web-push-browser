import { generateKeyPair, exportJWK } from "jose";

export async function generateVapidKeys() {
	const { publicKey, privateKey } = await generateKeyPair("ES256");

	return { publicKey, privateKey };
}
