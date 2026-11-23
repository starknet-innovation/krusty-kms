/** Independently verify the Rust selector fixture with starknet.js. */

import { readFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { hash } from "starknet";

interface Fixture {
  vectors: { name: string; selector: string }[];
}

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../crates/kms/tests/fixtures/selector_vectors.json"
);
const fixture: Fixture = JSON.parse(readFileSync(fixturePath, "utf8"));

let failures = 0;
for (const { name, selector } of fixture.vectors) {
  const actual = hash.getSelectorFromName(name);
  if (BigInt(actual) === BigInt(selector)) {
    console.log(`PASS ${JSON.stringify(name)}`);
  } else {
    console.error(`FAIL ${JSON.stringify(name)}: expected ${selector}, got ${actual}`);
    failures += 1;
  }
}

if (fixture.vectors.length === 0 || failures > 0) {
  console.error(`${failures} selector vector(s) failed`);
  process.exit(1);
}
