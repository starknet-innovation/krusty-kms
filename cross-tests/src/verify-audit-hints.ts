/** Decrypt Rust operation hints with the pinned Tongo 1.3.2 auditor primitives. */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ProjectivePoint } from "@fatsolutions/tongo-sdk";

// The package exports only its root, so resolve its exact installed modules.
const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const sdk = resolve(here, "../node_modules/@fatsolutions/tongo-sdk/dist");
const { ECDiffieHellman, deriveSymmetricEncryptionKey } = require(
  resolve(sdk, "key.js")
);
const { AEChaCha, AEHintToBytes } = require(resolve(sdk, "ae_balance.js"));
const { CairoUint512, uint256 } = require(
  resolve(sdk, "../node_modules/starknet")
);

interface HintVector {
  name: string;
  balance: string;
  account_nonce: string;
  tongo_address: string;
  auditor_private_key: string;
  user_public_key: { x: string; y: string };
  hint_ciphertext: string;
  hint_nonce: string;
  cairo_hint: [string, string, string, string, string, string];
}

const input = resolve(here, "../../cross-audit-hint-vectors.json");
const vectors = JSON.parse(readFileSync(input, "utf8")) as HintVector[];
assert.equal(vectors.length, 5, "expected all four audited operations");

for (const vector of vectors) {
  const publicKey = new ProjectivePoint(
    BigInt(vector.user_public_key.x),
    BigInt(vector.user_public_key.y),
    1n
  );
  const shared = ECDiffieHellman(
    BigInt(vector.auditor_private_key),
    publicKey.toRawBytes(true)
  );
  const key = await deriveSymmetricEncryptionKey({
    contractAddress: vector.tongo_address,
    nonce: BigInt(vector.account_nonce),
    secret: shared,
  });
  const cipher = new AEChaCha(key);
  const [limb0, limb1, limb2, limb3, low, high] = vector.cairo_hint;
  const ciphertext = new CairoUint512({
    limb0,
    limb1,
    limb2,
    limb3,
  }).toBigInt();
  const nonce = uint256.uint256ToBN({ low, high });
  assert.equal(ciphertext, BigInt(`0x${vector.hint_ciphertext}`));
  assert.equal(nonce, BigInt(`0x${vector.hint_nonce}`));
  const hint = AEHintToBytes({ ciphertext, nonce });
  assert.equal(
    cipher.decryptBalance(hint),
    BigInt(vector.balance),
    `${vector.name}: auditor recovered a different balance`
  );
  console.log(`PASS ${vector.name}: auditor decrypted ${vector.balance}`);
}

console.log(`Verified ${vectors.length} Rust audit hints with pinned Tongo`);
