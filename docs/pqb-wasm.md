# PQB in the WASM npm package

Import `WasmPqbVault` from `@starknetfoundation/krusty-kms-wasm` after the usual
WASM initialization. These additive exports are introduced in **3.1.0**; the
immutable published 3.0.0 package has no PQB exports. The 3.1.0 release must complete
[the release playbook](crates-release.md) before packages become available.
Merging the release version bump starts the npm workflow, which needs
protected-environment approval. Bramble must pin the new immutable published
3.1.0 version before shipping; a source merge alone does not make it available.

## Flow

```ts
import { WasmPqbVault } from '@starknetfoundation/krusty-kms-wasm';

// After WASM initialization. phrase/passphrase come from the wallet secret store.
const vault = WasmPqbVault.fromMnemonic(phrase, childIndex, 'main', passphrase);
// Restore instead: WasmPqbVault.fromChildMnemonic(childWords24, 'main').
let request;
try {
  const material = vault.publicMaterial();
  // Caller verifies funding, recipients, fees, all three puzzle hits and transaction.
  request = vault.prepareDisclosure(unsignedTxHex, vaultInputIndex,
    material.scriptSha256, round0Indices8, round1Indices9, menuIndices3);
  const info = request.info();
  // Atomic durable journal: reserve for this vault or accept an EXACT retry only.
  // This must survive crashes/restores and exclude concurrent conflicting writers.
  // Any existing different digest is permanently refused; do not reset on restore.
  await journal.recordExposureDurably(material.scriptSha256, info.digest);
  const disclosure = vault.authorize(request);
  // Public assembly adapter consumes disclosure, material and verified puzzle keys.
  // Do not feed a seed to the SDK's seed-bearing buildLock/assemblePqb flow.
  return { info, disclosure };
} finally {
  request?.dispose(); request?.free();
  vault.dispose(); vault.free();
}
```

`dispose()` is idempotent and drops the Rust owner; subsequent operations fail.
`free()` releases the wasm-bindgen wrapper as well. Never use a wrapper after
`free()`. Prepared requests contain private Rust fields, not editable JS request
data. Mutating `info()` or `publicMaterial()` copies does not change authorization.
A request from another vault fails. An exact retry returns identical bytes.
The native vault reuses immutable public material across these operations; returned
JS public objects remain independent copies. No secret witness table is cached.
Computing a digest is **not** exposure prevention: the caller's durable journal
must permanently reject a different digest even after process loss or restoration.
Each BIP85 child may back at most one vault. Restoration does not recover a journal.

## Exact API and response shapes

All byte strings below are **lowercase hex, without `0x`, in byte order** (no
Bitcoin display-hash reversal). Transactions are full canonical unsigned legacy
serialization with every scriptSig empty and no witness, at most 50,000 bytes.
Input indices refer to that transaction, starting at zero. No signing-digest input
is accepted. Numbers must be finite nonnegative exact integers within their field
range; selections and PSBT input indices must be plain JS arrays, not typed arrays.

- `WasmPqbVault.fromMnemonic(phrase: string, index: number, network: string,
  passphrase?: string | null): WasmPqbVault` derives BIP85 at
  `m/83696968'/39'/0'/24'/index'` with `index < 2^31`. Omitted passphrase means empty.
- `WasmPqbVault.fromChildMnemonic(words: string, network: string): WasmPqbVault`
  restores the **24-word child**, rather than treating it as a new root.
- Networks are exactly `main`, `testnet4`, `regtest`; the network binds derivation
  and is retained for `deposit()`. Network text is checked as at most eight JS
  characters before copying. No default network or secret export exists.
- `publicMaterial(): PqbPublicMaterial` returns:
  `{ script, scriptSha256, commitments, cosigPublicKey, menus }`.
  `script` is 4,908 bytes; `scriptSha256` is 32 bytes; `commitments` is 109
  20-byte strings in table-index order; `cosigPublicKey` is compressed SEC1
  (33 bytes). `menus` is `[pinning, round0, round1]`, each
  `{ r, commitments, recoveryPoints }`. `r` is 32-byte big-endian;
  commitments are 20-byte SHA1 values in menu-index order (12,16,16 entries).
  `recoveryPoints[variantIndex][menuIndex]` contains uncompressed SEC1 (65-byte)
  points. Variants follow `(r,even),(r,odd),(r+n,even),(r+n,odd)` where they exist:
  pinning has two variants, each round has four.
- `prepareDisclosure(txHex: string, inputIndex: number, expectedScriptHash: string,
  round0: number[], round1: number[], menus: number[]): WasmPqbRequest`.
  `expectedScriptHash` is checked as exactly 64 JS characters before copying,
  then validated as 32 lowercase hex bytes. HORS arrays have exactly 8 and 9
  indices, each below 109, distinct within and across rounds. Menus have three
  indices below 12,16,16. **All ordering is preserved**, never sorted.
- `request.info(): PqbRequestInfo` returns
  `{ digest, cosigSighash, stageSighashes: [pinning, round0, round1] }`, all
  32-byte strings. `digest` is the journal format in [PQB KMS](pqb-kms.md).
- `authorize(request: WasmPqbRequest): PqbDisclosure` returns
  `{ round0: string[8], round1: string[9], menus: [string,string,string],
  cosignature: string }`. Round preimages are 20 and 32 bytes respectively, in
  selection order. Menus are selected DER signatures in pinning/round0/round1
  order, and `cosignature` is the transaction's RFC6979 low-S co-signature.
  All signatures include trailing SIGHASH_ALL byte `01`. No unselected witnesses
  are returned. This is **not** Config A's 8+7 QSB disclosure format.
- `deposit(): PqbDeposit` returns `{ address, scriptPubkey, publicKey }`:
  network-specific Bech32 P2WPKH address, 22-byte output script and compressed
  33-byte SEC1 key.
- `signDepositPsbt(psbtBase64: string, inputIndices: number[]): string` returns
  a version-0 PSBT as base64. Base64 text is checked in JS before copying and
  limited to 5,592,408 characters (the encoded 4 MiB limit); Rust additionally
  limits the decoded PSBT to 4 MiB. Rust requires matching full `non_witness_utxo` and
  `witness_utxo`, owned P2WPKH inputs, and SIGHASH_ALL (absent means ALL).
  No finalization or broadcast. Wrong ownership, conflicting UTXOs, unsupported
  sighashes, invalid or duplicate indices fail.

Errors throw; no partial disclosure result is returned. Mnemonic/passphrase WASM
buffers and Rust secret owners are zeroized; compiler/dependency copies and the
source JS strings are outside that guarantee. Returned disclosure copies in
JavaScript **cannot be reliably wiped**. Retain as little as necessary.
The KMS does not verify puzzle hits, funding, recipients, fees or Bitcoin consensus.
Those checks, scriptSig assembly and the durable exposure journal belong to callers.

## QSB SDK adapter and compatibility

Inspected qsb-app `f76891fb1a67f25d5dc97afd4e23ede707cd77d1`, whose vendored PQB
core records fireblocks-labs/pqb `eccdd09772edf14ab37fc63992b0626ad7ff2221`, the
same source as Krusty's committed Python/TypeScript vectors. The current
`sdk/runtime.ts`/`src/lib/pqb.ts` flow accepts seed-bearing recovery state;
Bramble needs a public-material/selected-witness adapter before it can use this
Krusty boundary end to end. Krusty supplies the exact script and public menu points;
the adapter can derive the public grinder packet from them. In the SDK packet,
`round_table` is the deterministic dummy-signature table (not HORS commitments),
and menu variants match `recoveryPoints[variant][menu]`.
Use the SDK's public packet/hit checking logic and preserve canonical variant flags.
Do not substitute `commitments` for `round_table` or call seed-taking `buildLock`.
SDK registration, real puzzle solving, assembly and on-chain spending are separate
integration work; the compatibility vectors are assembly cases, not real solves.

Bramble's Nostr adapter must also accept the existing `openNostrApplicationData`
**JSON string** result after parsing:
`{ content: string, identifier: string, senderPublicKey: string, wrapId: string,
rumorId: string, createdAt: string }`. `createdAt` is a decimal string so the full
u64 timestamp survives JS parsing. Keep all three metadata fields; they support
replay checks. These fields are unchanged by the PQB addition.

## Reproduce compatibility evidence

`bash tools/check.sh wasm` runs the existing WASM suites (including committed
Python/TypeScript script, menu, spend and deposit fixtures), builds the actual web
package, checks generated TypeScript declarations with a consumer, then runs
`cross-tests/src/verify-pqb-wasm.mjs` against that package. The latter compares
all public script/menu bytes and a non-sorted 8+9/three-menu disclosure to
`cross-tests/fixtures/pqb-wasm.json`, generated independently through the QSB
vendored TypeScript core. It also checks all committed wallet derivations,
child restoration vectors, network binding, the journal digest, retries, invalid
JS values, wrong vault/script, malformed transactions, disposal, strict deposit
PSBT rules and existing QSB exports.

Regenerate the additional public fixture from the inspected QSB checkout:

```sh
node --import /path/to/qsb-app/node_modules/tsx/dist/loader.mjs \
  tools/pqb-wasm-vectors.mjs /path/to/qsb-app > cross-tests/fixtures/pqb-wasm.json
```

Use the recorded QSB commit, with its dependencies installed. All fixture secrets
are public test values, never fund them. No reference dependency is required for
the committed offline checks. See [PQB KMS](pqb-kms.md) for the original Python
exporter and TypeScript verifier.
