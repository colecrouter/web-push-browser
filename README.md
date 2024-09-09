# web-push-browser

> This project is not affiliated or based upon the original [web-push](https://github.com/web-push-libs/web-push) package or [web-push-lib](https://github.com/web-push-libs) organization.

This package is aimed at being a lightweight replacement for [web-push](https://github.com/web-push-libs/web-push), as (at the time of writing) it relies on Node.js dependencies that are not available in the browser.

## Installation

```bash
npm install web-push-browser
```

## Example Usage

### Subscribing a User

```ts
import { fromBase64Url } from 'web-push-browser';

//...

const registration = await navigator.serviceWorker.register('./service-worker.js', { type: 'module' });
try {
    // Subscribe to push notifications
    const sub = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: fromBase64Url(PUBLIC_VAPID_KEY),
    });

    // Store the subscription in your backend
    // ...
} catch (err) {
    console.error('Failed to subscribe to notifications', err);
    if (await registration.pushManager.getSubscription()) {
        // Cleanup if existing subscription exists
        await sub.unsubscribe();
    }
}
```

### Sending a Push Notification

```ts
import { sendNotification, deserializeVapidKeys } from 'web-push-browser';

// You can use `deserializeVapidKeys` to convert your VAPID keys from strings into a KeyPair
const keyPair = await deserializeVapidKeys({
    publicKey: PUBLIC_VAPID_KEY,
    privateKey: VAPID_PRIVATE_KEY,
});

const sub = // Get the subscription from your backend
const { auth, p256dh } = sub.keys;

const res = await sendPushNotification(
    keyPair,
    {
        endpoint: sub.endpoint,
        keys: {
            auth: auth,
            p256dh: p256dh,
        },
    },
    "support@website.com",
    JSON.stringify("Insert JSON payload here"),
);
if (!res.ok) {
    console.error('Failed to send push notification', res);
}
```

### Generating VAPID Keys

```js
import { generateVapidKeys, serializeVapidKeys } from 'web-push-browser';

const keys = await generateVapidKeys();
const serializedKeys = await serializeVapidKeys(keys);
console.log(serializedKeys);
```

## Extended Usage

This package only supports the basic functionality. If you need more advanced features, such as proxies, custom headers, etc. you can access the internal functions to create your own requests.