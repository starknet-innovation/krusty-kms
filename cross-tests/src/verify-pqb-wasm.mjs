// Exercise the actual generated web package, including wasm-bindgen JS conversions.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { WasmPqbVault, initSync, deriveQsbCommitments, qsbRevealDigest,
  revealQsbPreimages, getVersion, poseidonHash } from '../../crates/wasm/pkg/krusty_kms_wasm.js';
initSync({ module: readFileSync(new URL('../../crates/wasm/pkg/krusty_kms_wasm_bg.wasm', import.meta.url)) });
const v = JSON.parse(readFileSync(new URL('../fixtures/pqb-wasm.json', import.meta.url)));
const native = JSON.parse(readFileSync(new URL('../../crates/kms/tests/fixtures/pqb_kms_vectors.json', import.meta.url)));
const { mnemonic, index, network, passphrase } = v.wallet;
const derive = (i = index, net = network, pass = passphrase) => WasmPqbVault.fromMnemonic(mnemonic,i,net,pass);
const vault = derive();
const hash = v.publicMaterial.scriptSha256;
const prepare = (tx = v.transaction, idx = 0, h = hash, a = v.round0, b = v.round1, m = v.menus) =>
  vault.prepareDisclosure(tx,idx,h,a,b,m);
const drop = handle => { handle.dispose(); handle.free(); };
const hashBytes = b => createHash('sha256').update(b).digest();
const bytes = h => Buffer.from(h, 'hex');
const hex = b => Buffer.from(b).toString('hex');
try {
  assert.equal(typeof getVersion(), 'string');
  assert.match(poseidonHash('0x1','0x2'), /^0x/);
  assert.deepEqual(vault.publicMaterial(), v.publicMaterial);
  const changedCopy = vault.publicMaterial(); changedCopy.script = '';
  assert.deepEqual(vault.publicMaterial(), v.publicMaterial);
  // Every committed wallet derivation, passphrase and network case.
  for (const w of native.wallets) {
    const h = WasmPqbVault.fromMnemonic(w.mnemonic,w.index,w.network,w.passphrase);
    assert.equal(h.publicMaterial().scriptSha256,w.script_sha256); drop(h);
  }
  // Committed BIP85 child restorations checked against the TypeScript reference.
  for (const c of v.restoration) {
    const restored = WasmPqbVault.fromChildMnemonic(c.words,c.network);
    assert.equal(restored.publicMaterial().scriptSha256,c.scriptSha256); drop(restored);
  }
  const networkHashes = new Set();
  for (const net of ['main','testnet4','regtest']) {
    const h = derive(index,net);
    networkHashes.add(h.publicMaterial().scriptSha256);
    assert.ok(h.deposit().address.startsWith({main:'bc1',testnet4:'tb1',regtest:'bcrt1'}[net]));
    drop(h);
  }
  assert.equal(networkHashes.size,3);
  const request = prepare();
  try {
    const info = request.info();
    assert.deepEqual(info.stageSighashes, v.info.stageSighashes);
    assert.equal(info.cosigSighash,v.info.cosigSighash);
    const digest = hashBytes(Buffer.concat([Buffer.from('krusty/pqb/disclosure/v1\0'),bytes(hash),
      Buffer.alloc(8),Buffer.from([...v.round0,...v.round1,...v.menus]),bytes(v.transaction)]));
    assert.equal(info.digest,hex(digest));
    info.cosigSighash = '00'.repeat(32); info.digest = '';
    assert.deepEqual(vault.authorize(request), v.disclosure);
    assert.deepEqual(vault.authorize(request), vault.authorize(request));
    const retry = prepare(); assert.deepEqual(retry.info(),request.info()); drop(retry);
    for (const changed of [
      prepare(v.transaction.slice(0,-8) + '01000000'),
      prepare(v.transaction,0,hash,[...v.round0].reverse()),
      prepare(v.transaction,0,hash,v.round0,v.round1,[0,0,0]),
    ]) { assert.notEqual(changed.info().digest,request.info().digest); drop(changed); }
    const other = derive(1); assert.throws(() => other.authorize(request)); drop(other);
    // Mutable JS object data is never accepted as a validated request handle.
    for (const bad of [{},null,undefined,request.info(),v.disclosure,0])
      assert.throws(() => vault.authorize(bad));
    request.dispose(); request.dispose();
    assert.throws(() => request.info()); assert.throws(() => vault.authorize(request));
  } finally { drop(request); }
  // Validate JS values before wasm-bindgen can narrow or wrap them.
  for (const n of [-1,0.5,NaN,Infinity,2**31,2**32,Number.MAX_SAFE_INTEGER,'0',null,undefined,true,0n]) {
    assert.throws(() => WasmPqbVault.fromMnemonic(mnemonic,n,network));
  }
  for (const net of ['', 'mainnet','testnet','MAIN']) assert.throws(() => derive(0,net));
  assert.throws(() => WasmPqbVault.fromChildMnemonic(mnemonic,'main'));
  assert.throws(() => WasmPqbVault.fromMnemonic('bad',0,'main'));
  for (const n of [-1,0.5,NaN,Infinity,2**32,'0',null,undefined,true,0n]) {
    assert.throws(() => vault.prepareDisclosure(v.transaction,n,hash,v.round0,v.round1,v.menus));
    assert.throws(() => prepare(v.transaction,0,hash,[n,...v.round0.slice(1)]));
    assert.throws(() => prepare(v.transaction,0,hash,v.round0,[n,...v.round1.slice(1)]));
    assert.throws(() => prepare(v.transaction,0,hash,v.round0,v.round1,[n,0,0]));
  }
  for (const bad of [[],new Uint8Array(v.round0),[...v.round0,1],[256,...v.round0.slice(1)],
    [109,...v.round0.slice(1)],[v.round1[0],...v.round0.slice(1)],Array(8),
    [v.round0[1],...v.round0.slice(1)]]) assert.throws(() => prepare(v.transaction,0,hash,bad));
  for (const menus of [[12,0,0],[0,16,0],[0,0,16],new Uint8Array([0,0,0]),[0,0]])
    assert.throws(() => prepare(v.transaction,0,hash,v.round0,v.round1,menus));
  for (const h of ['00'.repeat(32),hash.toUpperCase(),'0x'+hash,hash.slice(2)])
    assert.throws(() => prepare(v.transaction,0,h));
  for (const tx of ['', '00',v.transaction+'00',v.transaction.toUpperCase(),'0x'+v.transaction,
    '00'.repeat(50001), {},null,23]) assert.throws(() => prepare(tx));
  for (let i = 0; i < v.transaction.length; i += 2) assert.throws(() => prepare(v.transaction.slice(0,i)));
  assert.throws(() => prepare(v.transaction,1));
  // Strict version-0 PSBT: real full funding transaction + matching witness UTXO.
  const u32 = n => { const b=Buffer.alloc(4); b.writeUInt32LE(n); return b; };
  const u64 = n => { const b=Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
  const concat = (...a) => Buffer.concat(a);
  const varbytes = b => concat(Buffer.from([b.length]),b);
  const out = (amount,script) => concat(u64(amount),varbytes(script));
  const tx = (prev,output) => concat(u32(2),Buffer.from([1]),prev,u32(0),Buffer.from([0]),
    u32(0xffffffff),Buffer.from([1]),output,u32(0));
  const deposit = vault.deposit();
  const fundingOutput = out(100000,bytes(deposit.scriptPubkey));
  const funding = tx(Buffer.alloc(32,0x7b),fundingOutput);
  const spend = tx(hashBytes(hashBytes(funding)),out(99000,Buffer.from([0x51])));
  const pair = (key,val) => concat(varbytes(Buffer.from([key])),varbytes(val));
  const psbt = (sighash, witness = fundingOutput, full = funding) => concat(
    bytes('70736274ff'), pair(0,spend), Buffer.from([0]),
    ...(full ? [pair(0,full)] : []), ...(witness ? [pair(1,witness)] : []),
    ...(sighash === undefined ? [] : [pair(3,u32(sighash))]),Buffer.from([0,0])).toString('base64');
  const signed = vault.signDepositPsbt(psbt(),[0]);
  assert.equal(signed,vault.signDepositPsbt(psbt(),[0]));
  assert.notEqual(signed,psbt());
  assert.ok(bytes(Buffer.from(signed,'base64').toString('hex')).includes(bytes(deposit.publicKey)));
  assert.doesNotThrow(() => vault.signDepositPsbt(psbt(1),[0]));
  for (const mode of [0,2,3,0x81,0x82,0x83]) assert.throws(() => vault.signDepositPsbt(psbt(mode),[0]));
  assert.throws(() => vault.signDepositPsbt(psbt(undefined,null),[0]));
  assert.throws(() => vault.signDepositPsbt(psbt(undefined,fundingOutput,null),[0]));
  assert.throws(() => vault.signDepositPsbt(psbt(undefined,out(99999,bytes(deposit.scriptPubkey))),[0]));
  const other = derive(2); assert.throws(() => other.signDepositPsbt(psbt(),[0])); drop(other);
  for (const inputs of [[],[1],[0,0],[-1],[0.1],[2**32],[NaN],['0'],new Uint32Array([0])])
    assert.throws(() => vault.signDepositPsbt(psbt(),inputs));
  assert.throws(() => vault.signDepositPsbt('bad',[0]));
  vault.dispose(); vault.dispose();
  for (const call of [()=>vault.publicMaterial(),()=>vault.deposit(),()=>prepare(),
    ()=>vault.signDepositPsbt(psbt(),[0])]) assert.throws(call);
} finally { drop(vault); }
// QSB-HORS-v1 remains a separate, working 8+7 interface.
const r0 = [0,1,2,3,4,5,6,7], r1 = [8,9,10,11,12,13,14];
const qsb = deriveQsbCommitments(mnemonic,0,0);
assert.equal(qsb.round0.length,150);
assert.equal(revealQsbPreimages(mnemonic,0,0,r0,r1).length,15);
assert.match(qsbRevealDigest(v.transaction,r0,r1).digest,/^[0-9a-f]{64}$/);
console.log('Built PQB WASM package: reference material/disclosure, JS validation, retry, disposal, deposit and QSB regression checks passed.');
