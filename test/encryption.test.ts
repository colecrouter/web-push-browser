import { encryptPayload } from "../src/crypto/encrypt";
import { fromBase64Url, toBase64Url } from "../src/utils/base64url";

let values: Awaited<ReturnType<typeof encryptPayload>>;

// DO NOT CHANGE THIS TEXT
const TEXT = "When I grow up, I want to be a watermelon";
const SUB = {
	endpoint: "https://fcm.googleapis.com/fcm/send/123456789",
	keys: {
		p256dh:
			"BEe7bEvNRAOgQnrbukIzZcbq9rVcROzE6YnE5VAQ5E0TzmDfU-dz9IC2p02sNSpfz5FSDsn7rvaPkwoA0ZTvsUY",
		auth: "kER9haBadZoLNuH-c44NXQ",
	},
};
const SALT = fromBase64Url("0KIyRvs_qdJGgjxbkBpzxw");
const APP_SERVER_PRIVATE_KEY_BYTES = fromBase64Url(
	"5gMll8lkpOU8VdZyjJsse_j8iNb9rBtP99f77F0z8Q0",
);
const APP_SERVER_PUBLIC_KEY_BYTES = fromBase64Url(
	"BMY6BhMeQ-kKPxbcbZdLRbZ9TmAP-TIrw7Y9kpRjLhKuyuStN_0S-N9fY5zgJeUA0bM-19SQo-HL3VzCxV13TEc",
);
let APP_SERVER_PUBLIC_KEY: CryptoKey;
let APP_SERVER_PRIVATE_KEY: CryptoKey;

const IKM = "Ly0vJBaYzaWl9lYiIScFUjXBhxPnTwLDFQcsGHU_xqE";
const PRK = "UAZoehRROrtGt5Ym2eaKXm-116r79yIx5xhGC8TQUMc";

beforeAll(async () => {
	APP_SERVER_PUBLIC_KEY = await crypto.subtle.importKey(
		"raw",
		APP_SERVER_PUBLIC_KEY_BYTES,
		{ name: "ECDH", namedCurve: "P-256" },
		true,
		[],
	);
	APP_SERVER_PRIVATE_KEY = await crypto.subtle.importKey(
		"jwk",
		{
			kty: "EC",
			crv: "P-256",
			d: toBase64Url(APP_SERVER_PRIVATE_KEY_BYTES),
			x: toBase64Url(APP_SERVER_PUBLIC_KEY_BYTES.slice(1, 33)),
			y: toBase64Url(APP_SERVER_PUBLIC_KEY_BYTES.slice(33, 66)),
		},
		{
			name: "ECDH",
			namedCurve: "P-256",
		},
		true,
		["deriveBits"],
	);

	values = await encryptPayload(TEXT, SUB.keys, {
		algorithm: "aes128gcm",
		salt: SALT,
		appServerKeyPair: {
			publicKey: APP_SERVER_PUBLIC_KEY,
			privateKey: APP_SERVER_PRIVATE_KEY,
		},
	});
});

describe("Push Notification Encryption and Decryption", () => {
	it("should have the correct PRK", () => {
		expect(toBase64Url(new Uint8Array(values.prk))).toBe(PRK);
	});
	it("should have the correct IKM", () => {
		expect(toBase64Url(new Uint8Array(values.ikm))).toBe(IKM);
	});

	// it("should decrypt the payload correctly", async () => {
	// 	const payload = await decryptPayload(values.encrypted.buffer, SUB.keys, {
	// 		appServerKeyPair: {
	// 			publicKey: APP_SERVER_PUBLIC_KEY,
	// 			privateKey: APP_SERVER_PRIVATE_KEY,
	// 		},
	// 		salt: SALT,
	// 		algorithm: "aes128gcm",
	// 	});
	// 	expect(payload).toBe(TEXT);
	// });
});
