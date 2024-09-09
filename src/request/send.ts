import { createJWT } from "../crypto/jwt.js";
import { encryptPayload } from "../crypto/payload.js";
import type { PushNotificationSubscription } from "../types.js";
import { generateHeaders } from "./generate.js";

/**
 * Send a push notification to a user.
 * @param vapidKeys - The VAPID keys to use for the request.
 * @param subscription - The PushSubscription to send the notification to.
 * @param email - The email address to use as the `sub` claim in the JWT. For example, `support@website.com`.
 * @param payload - The payload to send in the notification.
 * @returns The response from the push service.
 * @throws If any of the keys are unable to be parsed.
 */
export async function sendPushNotification(
	vapidKeys: CryptoKeyPair,
	subscription: PushNotificationSubscription,
	email: string,
	payload: string,
) {
	const jwt = await createJWT(
		vapidKeys.privateKey,
		new URL(subscription.endpoint),
		email,
	);
	const { encrypted, salt, serverPublicKey } = await encryptPayload(
		payload,
		subscription.keys,
	);
	const headers = await generateHeaders(
		vapidKeys.publicKey,
		jwt,
		encrypted,
		salt,
		serverPublicKey,
	);
	const request = new Request(subscription.endpoint, {
		method: "POST",
		headers,
		body: encrypted,
	});

	return fetch(request);
}
