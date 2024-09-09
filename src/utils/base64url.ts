/**
 * Convert a string or ArrayBuffer to a base64url encoded string
 * @param data - The data to encode.
 * @returns The base64url encoded string.
 */
export function toBase64Url<T extends ArrayBufferLike | string>(
	data: T,
): string {
	const base64 = btoa(
		typeof data === "string"
			? data
			: String.fromCharCode(...new Uint8Array(data)),
	);
	const base64Url = base64
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=/g, "");

	return base64Url;
}

/**
 * Convert a base64url encoded string to an ArrayBuffer
 * @param base64 - The base64url encoded string.
 * @returns The ArrayBuffer.
 */
export function fromBase64Url(base64: string): ArrayBuffer {
	const padding = "=".repeat((4 - (base64.length % 4)) % 4);
	const base64Padded = (base64 + padding).replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(base64Padded);
	const bytes = new Uint8Array(binary.length);

	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}

	return bytes.buffer;
}
