/**
 * Cross-language reference value verification: compute expected Starknet
 * cryptographic outputs using starknet.js v6 and assert they match pinned
 * reference constants.
 *
 * These same reference values should be used in Rust WASM binding tests to
 * guarantee cross-language compatibility.
 *
 * Usage: npx tsx src/verify-wasm-bindings.ts
 */

import { hash, ec, shortString } from "starknet";
import { readFileSync, writeFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Reference values (pinned constants shared with Rust test vectors)
// ---------------------------------------------------------------------------

const REF_PATH = resolve(__dirname, "reference-values.json");

interface ReferenceValues {
  description: string;
  pedersen: {
    hash_a_b: { inputs: string[]; expected: string };
    hash_on_elements: { inputs: string[]; expected: string };
  };
  poseidon: {
    hash_a_b: { inputs: string[]; expected: string };
    hash_on_elements: { inputs: string[]; expected: string };
  };
  keccak: {
    starknet_keccak: { input: string; expected: string };
    selector_from_name: { input: string; expected: string };
  };
  stark_key: {
    private_key: string;
    expected_public_key: string;
  };
  stark_sign: {
    private_key: string;
    message_hash: string;
    expected_r: string;
    expected_s: string;
  };
  contract_address: {
    oz_account: {
      salt: string;
      class_hash: string;
      deployer: string;
      expected: string;
    };
    argent_account: {
      class_hash: string;
      deployer: string;
      expected: string;
    };
  };
  short_string: {
    encode: { input: string; expected: string };
    decode: { input: string; expected: string };
  };
  grind_key: {
    seed: string;
    expected: string;
  };
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
let updated = false;

function assertEqual(testName: string, actual: string, expected: string): void {
  const normActual = actual.toLowerCase();
  const normExpected = expected.toLowerCase();
  if (normActual === normExpected) {
    console.log(`  PASS ${testName}`);
    passed++;
  } else {
    console.error(
      `  FAIL ${testName}\n       expected: ${expected}\n       actual:   ${actual}`
    );
    failed++;
  }
}

function pinAndAssert(
  testName: string,
  actual: string,
  refObj: { expected: string },
  refField: string
): void {
  if (!refObj.expected || refObj.expected === "") {
    // First run: pin the value
    console.log(`  PIN  ${testName}: ${actual}`);
    (refObj as Record<string, string>).expected = actual;
    updated = true;
    passed++;
  } else {
    assertEqual(testName, actual, refObj.expected);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const ref: ReferenceValues = JSON.parse(readFileSync(REF_PATH, "utf-8"));

  console.log("Starknet.js WASM binding reference value verification\n");

  // -------------------------------------------------------------------------
  // 1. Pedersen hash
  // -------------------------------------------------------------------------
  console.log("Pedersen hash:");
  {
    const result = hash.computePedersenHash("0x1", "0x2");
    assertEqual("pedersen_hash(0x1, 0x2)", result, ref.pedersen.hash_a_b.expected);
  }
  {
    const result = hash.computeHashOnElements(["0x1", "0x2", "0x3"]);
    assertEqual(
      "pedersen_hash_on_elements([0x1, 0x2, 0x3])",
      result,
      ref.pedersen.hash_on_elements.expected
    );
  }

  // -------------------------------------------------------------------------
  // 2. Poseidon hash
  // -------------------------------------------------------------------------
  console.log("Poseidon hash:");
  {
    const result = hash.computePoseidonHash("0x1", "0x2");
    assertEqual("poseidon_hash(0x1, 0x2)", result, ref.poseidon.hash_a_b.expected);
  }
  {
    const result = hash.computePoseidonHashOnElements(["0x1", "0x2", "0x3"]);
    assertEqual(
      "poseidon_hash_on_elements([0x1, 0x2, 0x3])",
      result,
      ref.poseidon.hash_on_elements.expected
    );
  }

  // -------------------------------------------------------------------------
  // 3. Starknet Keccak + selector
  // -------------------------------------------------------------------------
  console.log("Starknet keccak + selector:");
  {
    const result = "0x" + hash.starknetKeccak(Buffer.from("transfer")).toString(16);
    assertEqual(
      "starknet_keccak('transfer')",
      result,
      ref.keccak.starknet_keccak.expected
    );
  }
  {
    const result = hash.getSelectorFromName("transfer");
    assertEqual(
      "selector_from_name('transfer')",
      result,
      ref.keccak.selector_from_name.expected
    );
  }

  // -------------------------------------------------------------------------
  // 4. Stark public key derivation
  // -------------------------------------------------------------------------
  console.log("Stark key derivation:");
  {
    const pubKey = ec.starkCurve.getStarkKey(ref.stark_key.private_key);
    assertEqual(
      "get_stark_key(privkey)",
      pubKey,
      ref.stark_key.expected_public_key
    );
  }

  // -------------------------------------------------------------------------
  // 5. Stark signing
  // -------------------------------------------------------------------------
  console.log("Stark signing:");
  {
    const privKey = ref.stark_sign.private_key;
    const msgHash = ref.stark_sign.message_hash;
    const sig = ec.starkCurve.sign(msgHash, privKey);
    const r = "0x" + sig.r.toString(16);
    const s = "0x" + sig.s.toString(16);

    pinAndAssert("stark_sign.r", r, ref.stark_sign, "expected_r");
    pinAndAssert("stark_sign.s", s, ref.stark_sign, "expected_s");

    // Also verify the signature
    const pubKey = ec.starkCurve.getStarkKey(privKey);
    const isValid = ec.starkCurve.verify(sig, msgHash, pubKey);
    if (isValid) {
      console.log(`  PASS stark_sign_verify`);
      passed++;
    } else {
      console.error(`  FAIL stark_sign_verify: signature did not verify`);
      failed++;
    }
  }

  // -------------------------------------------------------------------------
  // 6. Contract address computation
  // -------------------------------------------------------------------------
  console.log("Contract address:");
  {
    const pubKey = ec.starkCurve.getStarkKey(ref.stark_key.private_key);

    // OZ account
    const ozAddr = hash.calculateContractAddressFromHash(
      ref.contract_address.oz_account.salt,
      ref.contract_address.oz_account.class_hash,
      [pubKey],
      ref.contract_address.oz_account.deployer
    );
    pinAndAssert(
      "contract_address_oz",
      ozAddr,
      ref.contract_address.oz_account,
      "expected"
    );

    // Argent account
    const argentAddr = hash.calculateContractAddressFromHash(
      pubKey, // salt = publicKey
      ref.contract_address.argent_account.class_hash,
      ["0x0", pubKey, "0x0"],
      ref.contract_address.argent_account.deployer
    );
    pinAndAssert(
      "contract_address_argent",
      argentAddr,
      ref.contract_address.argent_account,
      "expected"
    );
  }

  // -------------------------------------------------------------------------
  // 7. Short string encoding
  // -------------------------------------------------------------------------
  console.log("Short string encoding:");
  {
    const encoded = shortString.encodeShortString("hello");
    assertEqual("encode_short_string('hello')", encoded, ref.short_string.encode.expected);
  }
  {
    const decoded = shortString.decodeShortString(ref.short_string.decode.input);
    if (decoded === ref.short_string.decode.expected) {
      console.log(`  PASS decode_short_string`);
      passed++;
    } else {
      console.error(
        `  FAIL decode_short_string\n       expected: ${ref.short_string.decode.expected}\n       actual:   ${decoded}`
      );
      failed++;
    }
  }

  // -------------------------------------------------------------------------
  // 8. grindKey
  // -------------------------------------------------------------------------
  console.log("grindKey:");
  {
    const result = ec.starkCurve.grindKey(ref.grind_key.seed);
    const resultHex = "0x" + BigInt(result).toString(16);
    assertEqual("grind_key(seed)", resultHex, ref.grind_key.expected);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log(`\nResults: ${passed} passed, ${failed} failed`);

  // Write back pinned values if any were newly computed
  if (updated) {
    writeFileSync(REF_PATH, JSON.stringify(ref, null, 2) + "\n");
    console.log(`\nUpdated reference values written to ${REF_PATH}`);
    console.log(
      "Please commit the updated reference-values.json and re-run to confirm."
    );
  }

  if (failed > 0) {
    process.exit(1);
  }
}

main();
