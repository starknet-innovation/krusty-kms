/** Independently verify the Rust SNIP-12 fixtures with starknet.js. */

import { readFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { typedData, type TypedData } from "starknet-10";
import {
  typedData as currentTypedData,
  type TypedData as CurrentTypedData,
} from "starknet";

interface Vector {
  name: string;
  account_address: string;
  expected_hash: string;
  typed_data: TypedData;
}

interface Fixture {
  source: string;
  vectors: Vector[];
}

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../crates/kms/tests/fixtures/snip12_typed_data_vectors.json"
);
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

let failures = 0;
for (const vector of fixture.vectors) {
  const actual = typedData.getMessageHash(vector.typed_data, vector.account_address);
  if (BigInt(actual) === BigInt(vector.expected_hash)) {
    console.log(`PASS ${vector.name}`);
  } else {
    console.error(
      `FAIL ${vector.name}: expected ${vector.expected_hash}, got ${actual}`
    );
    failures += 1;
  }
}

// These shapes differ in the pinned Rust encoder and are checked against the
// current starknet.js API independently of the Rust expected values.
const compatPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../crates/kms/tests/fixtures/snip12_starknet_js_10_8_vectors.json"
);
const compat: Fixture = JSON.parse(readFileSync(compatPath, "utf8"));
for (const vector of compat.vectors) {
  const actual = currentTypedData.getMessageHash(
    vector.typed_data as CurrentTypedData,
    vector.account_address
  );
  if (BigInt(actual) === BigInt(vector.expected_hash)) {
    console.log(`PASS ${vector.name}`);
  } else {
    console.error(
      `FAIL ${vector.name}: expected ${vector.expected_hash}, got ${actual}`
    );
    failures += 1;
  }
}

if (failures > 0) {
  process.exitCode = 1;
}
