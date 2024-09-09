import { type JWTPayload, SignJWT } from "jose";

export async function signRequest(payload: JWTPayload, privateKey: CryptoKey) {
	const jwt = await new SignJWT(payload)
		.setProtectedHeader({ alg: "ES256" })
		.sign(privateKey);
	return jwt;
}
