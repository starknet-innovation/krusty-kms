// PUBLIC TEST SEED ONLY. Generate through qsb-app's independently vendored PQB core.
// node --import /path/to/qsb-app/node_modules/tsx/dist/loader.mjs tools/pqb-wasm-vectors.mjs /path/to/qsb-app
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const ref = file => import(pathToFileURL(resolve(process.argv[2], 'src/pqb-core', file)));
const { buildLock } = await ref('lock.ts');
const { assemble, cosigSign } = await ref('spend.ts');
const { stagesFromLock } = await ref('grind.ts');
const { serializeTx } = await ref('tx.ts');
const { hex, fromHex, fromInt } = await ref('primitives.ts');
const v = JSON.parse(readFileSync(new URL('../crates/kms/tests/fixtures/pqb_kms_vectors.json', import.meta.url)));
const walletIndex = 0; // Reference the committed PUBLIC vector, without copying its input fields.
const lock = buildLock('PQB', fromHex(v.wallets[walletIndex].seed));
const round0 = [80,3,14,25,36,47,58,69], round1 = [98,10,21,32,43,54,65,76,87], menus = [11,15,14];
const spend = assemble(lock, { txid: 'cc'.repeat(32), vout: 1, amount: 250000 },
  [[242000, fromHex('0014000102030405060708090a0b0c0d0e0f10111213')]],
  { selection: [round0, round1], menuPick: {pin: menus[0], 0: menus[1], 1: menus[2]} });
spend.tx.vin.forEach(input => { input.scriptSig = new Uint8Array(); });
const stages = stagesFromLock(lock);
const ms = [lock.detail.menu, ...lock.detail.rmenu];
const publicMaterial = {
  script: hex(lock.script), scriptSha256: lock.sha256,
  commitments: lock.detail.comm.map(hex), cosigPublicKey: hex(lock.detail.cosig.pk),
  menus: ms.map((m, i) => ({ r: hex(fromInt(m.r,32)), commitments: m.comm.map(hex),
    recoveryPoints: stages[i].menuR.variants.map(v => v.points) })),
};
console.log(JSON.stringify({
  note: 'PUBLIC TEST VALUES ONLY. Assembly vector, not a solved puzzle.',
  qsbAppCommit: 'f76891fb1a67f25d5dc97afd4e23ede707cd77d1', sourceCommit: v.source_commit,
  walletIndex,
  restoration: v.bip85.children.flatMap(c => ['main','regtest'].map(network => ({
    words: c.words, network, scriptSha256: buildLock('PQB', fromHex(c.seeds[`PQB|True|${network}`])).sha256,
  }))),
  publicMaterial, transaction: hex(serializeTx(spend.tx)), round0, round1, menus,
  info: { cosigSighash: hex(fromInt(spend.zCosig,32)), stageSighashes: spend.z.map(z => hex(fromInt(z,32))) },
  disclosure: { round0: round0.map(i => hex(lock.detail.wit[0][i])),
    round1: round1.map(i => hex(lock.detail.wit[1][i])),
    menus: ms.map((m,i) => hex(m.sigs[menus[i]])),
    cosignature: hex(cosigSign(lock.detail.cosig.d, spend.zCosig)) },
}, null, 2));
