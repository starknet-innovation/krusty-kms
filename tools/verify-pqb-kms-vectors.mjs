// Check the extra Python-generated KMS fixtures with @pqb/core too.
// Usage: npm run build --prefix /path/to/pqb/js
//        node tools/verify-pqb-kms-vectors.mjs /path/to/pqb
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const reference = (file) => import(pathToFileURL(resolve(process.argv[2], 'js/dist/src', file)));
const { Root, child, vaultSeed } = await reference('keys.js');
const { buildLock } = await reference('lock.js');
const { sweep } = await reference('deposit.js');
const v = JSON.parse(readFileSync(new URL('../crates/kms/tests/fixtures/pqb_kms_vectors.json', import.meta.url)));
const bytes = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
for (const w of v.wallets) {
  const c = child(Root.fromMnemonic(w.mnemonic, w.passphrase), w.index);
  assert.equal(hex(c.entropy), w.entropy);
  const seed = vaultSeed(c.entropy, 'PQB', w.network);
  assert.equal(hex(seed), w.seed);
  assert.equal(buildLock('PQB', seed).sha256, w.script_sha256);
}
for (const p of v.deposit_psbts) {
  const result = sweep(bytes(p.seed), [{ txid: p.funding_txid, vout: 0, value: 100000, height: 1 }], bytes('51'), () => 1000);
  assert.equal(result.hex, p.signed_tx);
}
console.log(`TypeScript matched ${v.wallets.length} wallet derivations and ${v.deposit_psbts.length} deposit signatures.`);
