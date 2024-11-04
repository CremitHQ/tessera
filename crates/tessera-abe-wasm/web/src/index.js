import {
  mock_global_params,
  mock_authority,
  mock_user_secret_key,
  tessera_encrypt,
  tessera_decrypt,
} from "tessera-abe-wasm";

const gp = mock_global_params();
const authA = mock_authority(gp, "A");
const authB = mock_authority(gp, "B");
const aliceSecretKeyFromA = mock_user_secret_key(gp, authA.mk, "alice", [
  "admin",
  "ceo",
  "hr",
]);
const aliceSecretKeyFromB = mock_user_secret_key(gp, authB.mk, "alice", [
  "cto",
  "dev",
  "staff",
]);

const message = "Hello, Tessera!";
const policy = `"admin@A" and "cto@B" and "hr@A"`;

let elapsed = Date.now();
const ciphertext = tessera_encrypt(gp, [authA.pk, authB.pk], policy, message);
elapsed = Date.now() - elapsed;
console.log(`Encryption time: ${elapsed}ms`);
console.log(`Ciphertext: ${ciphertext}`);

elapsed = Date.now();
const aliceDecryptedMessage = tessera_decrypt(
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
  const bobDecryptedMessage = tessera_decrypt(
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
