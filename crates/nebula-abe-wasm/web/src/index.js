import {
	mock_authority,
	mock_global_params,
	mock_user_secret_key,
	nebula_decrypt,
	nebula_encrypt,
} from "nebula-abe-wasm";

const gp = mock_global_params();
const authA = mock_authority(gp, "A");
const authB = mock_authority(gp, "B");

const randomAttributes = new Array(30)
	.fill(0)
	.map((_) => `attr${Math.random().toString(36).substring(7)}`);
const aliceSecretKeyFromA = mock_user_secret_key(
	gp,
	authA.mk,
	"alice",
	["admin", "ceo", "hr"].concat(randomAttributes),
);
const aliceSecretKeyFromB = mock_user_secret_key(gp, authB.mk, "alice", [
	"cto",
	"dev",
	"staff",
]);

const message = "Hello, Nebula!";
const policy = randomAttributes.map((attr) => `"${attr}@A"`).join(" and ");

let elapsed = Date.now();
const ciphertext = nebula_encrypt(gp, [authA.pk, authB.pk], policy, message);
elapsed = Date.now() - elapsed;
console.log(`Encryption time: ${elapsed}ms`);
console.log(`Ciphertext: ${ciphertext}`);

elapsed = Date.now();
const aliceDecryptedMessage = nebula_decrypt(
	gp,
	[aliceSecretKeyFromA, aliceSecretKeyFromB],
	ciphertext,
);
elapsed = Date.now() - elapsed;
console.log(`Decryption time: ${elapsed}ms`);
console.log(`Decrypted message: ${aliceDecryptedMessage}`);

const bobSecretKeyFromA = mock_user_secret_key(gp, authA.mk, "bob", ["test"]);

try {
	elapsed = Date.now();
	const bobDecryptedMessage = nebula_decrypt(
		gp,
		[bobSecretKeyFromA],
		ciphertext,
	);
	elapsed = Date.now() - elapsed;
	console.log(`Decryption time: ${elapsed}ms`);
	console.log(`Decrypted message: ${bobDecryptedMessage}`);
} catch (e) {
	console.error(e.type, e.message);
}
