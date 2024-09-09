import { SignJWT } from "jose";
import { deriveSharedSecret } from "./crypto/deriveSharedSecret";
import { encryptPayload } from "./crypto/encryptPayload";
import { generateVapidKeys } from "./crypto/generateVapidKeys";
import { signRequest } from "./crypto/signRequest";
import type { PushNotificationOptions } from "./types";
import { createRequestHeaders } from "./utils/createRequestHeaders";
import { validateInputs } from "./utils/validateInputs";

export async function sendPushNotification(options: PushNotificationOptions) {
	if (!validateInputs(options)) {
		throw new Error("Invalid input");
	}

	// Generate VAPID keys
	const { publicKey, privateKey, publicKeyJWK } = await generateVapidKeys();

	const parsedUrl = new URL(options.sub.endpoint);
	const aud = `${parsedUrl.protocol}//${parsedUrl.host}`;
	const exp = options.sub.expirationTime ?? Math.floor(Date.now() / 1000) + 43200;
	const sub = `mailto:${options.email}`;

	const jwt = new SignJWT({
		aud,
		exp,
		sub,
	});

	const signedJWT = await jwt.sign(publicKey);

  const auth = options.sub.getKey("auth");
  const p256dh = options.sub.getKey("p256dh"); // base64url encoded

  const remotePublicKey = await crypto.subtle.importKey(

	const sharedSecret = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: p256dh,
    },
    privateKey,
    256 // 256 bits for P-256 is adequate
  );

	// Generate a random salt
	const salt = crypto.getRandomValues(new Uint8Array(16));

	// Encrypt the payload
	const encryptedPayload = await encryptPayload(
		options.payload,
		sharedSecret,
		salt,
	);

	// Convert JWK to CryptoKey for signing
	const privateECDSAKey = await crypto.subtle.importKey(
		"jwk",
		privateJWK,
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		true,
		["sign"],
	);

	// Sign the request
	const signedRequest = await signRequest(
		{ payload: encryptedPayload },
		privateECDSAKey,
	);

	// Create request headers
	const headers = createRequestHeaders(
		encryptedPayload,
		publicJWK,
		salt,
		options.ttl,
	);

	console.log(headers);

	// Send the push notification
	const response = await fetch(options.endpoint, {
		method: "POST",
		headers: {
			...headers,
			Authorization: `Bearer ${signedRequest}`,
		},
		body: options.payload,
	});

	return response;
}
