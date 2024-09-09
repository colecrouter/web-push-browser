import { SignJWT } from "jose";

/**
 * Generate and sign a JWT token.
 *
 * To be used in the `Authorization` header of a POST request to a web Push API endpoint.
 * @param privateVapidKey - The private key to sign the JWT with.
 * @param endpoint - The URL of the web Push API endpoint.
 * @param email - The email address to use as the `sub` claim. For example, `support@website.com`.
 * @returns
 */
export async function createJWT(
	privateVapidKey: CryptoKey,
	endpoint: URL,
	email: string,
): Promise<string> {
	const aud = endpoint.origin;
	const exp = Math.floor(Date.now() / 1000) + 12 * 60 * 60; // 12 hours from now
	const sub = `mailto:${email}`;

	return await new SignJWT({
		aud,
		exp,
		sub,
	})
		.setProtectedHeader({ alg: "ES256", typ: "JWT" })
		.sign(privateVapidKey);
}
