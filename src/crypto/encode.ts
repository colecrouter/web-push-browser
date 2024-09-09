// Uint8Array -> base64url string
export function encode(input: Uint8Array): string {
	return btoa(String.fromCharCode(...input));
}
