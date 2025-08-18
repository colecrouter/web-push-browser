# web-push-browser

> This project is not affiliated or based upon the original [web-push](https://github.com/web-push-libs/web-push) package or [web-push-lib](https://github.com/web-push-libs) organization.

Minimal, zero-dependency library for creating and sending Web Push (VAPID) notifications from environments without Node.js crypto shims — for example browsers, Cloudflare Workers, Deno, Bun, and other edge runtimes.

Key features:

- Runs in browsers, Cloudflare Workers, Deno, Bun, and Node
- Zero dependencies; ESM-first and browser-friendly
- VAPID key generation, serialization/deserialization
- Payload encryption with aes128gcm (aesgcm partially supported)
- Helper to generate the correct Web Push request headers and send the POST

Install

```bash
npm install web-push-browser
```

## Subscribing to Push Notifications (Client)

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

## Sending a Push Notification (Server)

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

> [!NOTE]
> `aesgcm` is not completely implemented in this package. Please use `aes128gcm` instead.
