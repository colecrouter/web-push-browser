export interface PushNotificationOptions {
	sub: PushSubscription;
	email: string;
	payload: string;
	ttl: number;
}
