# Account classes carry a role: deployment or implementation

Date: 2026-09-21. Status: accepted. Origin: issue #146.

## Problem

A class hash plays one of two roles for an account. A **deployment** class is
the `class_hash` of the `DEPLOY_ACCOUNT` transaction; it fixes the address and
is the only class an address can be derived from. An **implementation** class
is what the account runs after upgrading; it is what `starknet_getClassHashAt`
returns and what a signer must accept, and it never fixes an address.

Braavos separates the two by design: every account deploys with a *base* class
whose constructor is `[public_key]`, the target implementation travels in the
deploy signature, and the base class swaps itself out with
`replace_class_syscall` in the same transaction. No Braavos account runs the
class it was deployed with.

The published surface conflated the roles. `getAccountClassHashes()` returned
a flat `braavos: { "1.0.0", "legacy" }`, where `"1.0.0"` was actually the base
class introduced in v1.1.0 and `"legacy"` was the v1.0.0 *implementation*.
Neither the v1.0.0 base class (`0x013bfe…8e6`) nor the v1.1.0/v1.2.0
implementations (`0x02c8c7…74bc`, `0x03957f…bf8a`) were listed.
`deriveBraavosAccountAddress(pk, legacy)` derived an address no deployment can
produce, silently. Measured against 300 live Mainnet accounts by the reporter,
the set reproduced 43% of Braavos accounts; the v1.0.0 base class alone
accounts for a further 7 of 72 reproducible ones.

On the Argent side, discovery under direct derivation tried only v0.4.0
(v0.3.x accounts were unreachable), the Cairo 0 labels in the WASM map were
off by one version with `"0.2.0"` duplicating the proxy hash, and v0.5.0 was
unknown. The reporter's follow-up corrected their Argent numbers: with the
right calldata, 127 of 150 accounts reproduce (`(pk, 0)` on 0.3.x, `(0, pk,
1)` on guardian-less 0.4.0, `(0, pk, 0, 0, guardian)` on the rest), and the
class hash was never the problem. What let them pair the right class with the
wrong calldata was a flat set with no constructor convention attached, and
the convention varies by version *and* by guardian presence. Nothing
expressed the resulting split either: an account with a guardian cannot be
**discovered** from a phrase (the guardian is per-account, 38 distinct values
in 40 sampled, and part of the address), yet it can be **verified** once its
address is known, because the guardian is readable on chain. A caller that
cannot tell "not discoverable" from "no such account" tells users their funds
are gone.

## Decision

- **Registry.** `known_account_classes()` is the one table of known classes,
  each a `KnownAccountClass { family, class_hash, version, label, roles,
  constructor, source }`. `roles` is `deployment`, `implementation` or both;
  `constructor` is the calldata shape for a seed-derived key and is present
  exactly for deployment classes; `source` is the vendor's public listing the
  entry was checked against. `lookup_account_class`, `deployment_classes` and
  `implementation_classes` read it. WASM exposes it as
  `getAccountClassRegistry()`.
- **Braavos.** `BraavosAccount` moves to `account_class/braavos.rs` and gains
  the v1.0.0 base (`BASE_CLASS_HASH_V100`) and the v1.1.0 / v1.2.0
  implementations. `deployment_class_hashes()` and
  `implementation_class_hashes()` are disjoint. `try_with_class_hash` accepts a
  base class and rejects a known implementation class or an unknown hash;
  `with_class_hash` stays unchecked. The WASM `deriveBraavosAccountAddress`
  and the gateway use the checked path; the gateway allowlist holds base
  classes only and the `allow_unlisted_class_hash` override cannot admit an
  implementation class (it still admits an unknown one). Discovery emits one
  Braavos candidate per base class.
- **Argent.** v0.5.0 is a known class with the v0.4.0 layout, verified from
  the `constructor(owner: Signer, guardian: Option<Signer>)` signature and the
  unchanged `Signer` enum at tag `v0.5.0`. The default preset stays v0.4.0 so
  derived addresses are stable. Discovery tries every known Cairo 1 class under
  both key schemes. The Cairo 0 constants move to `ArgentCairo0` and the WASM
  labels follow Argent X's own constants (0.2.4, 0.2.3, 0.2.2, 0.2.1).
- **Convention with the class.** `KnownAccountClass::constructor` serialises
  as `{ shape, fromSeed, withGuardian, inputsOutsideSeed }`: the calldata a
  seed reproduces, the calldata once a guardian is set, and which inputs a
  phrase cannot supply. `constructor_calldata_with_guardian` (layout, preset
  and Cairo 0 proxy) builds the guardian form; WASM exposes it as
  `deriveArgentAccountAddressWithGuardian` for the verification path.
- **Derivability.** `ArgentConstructorLayout::decode` reads on-chain calldata
  back into owner kind, owner key and guardian key.
  `inspect_deployment(class_hash, salt, constructor_calldata)` takes the three
  `DEPLOY_ACCOUNT` fields and returns `FromSeed`, `NotFromSeed(reason)` with
  `Guardian | NonStarknetOwner | SaltNotPublicKey | ImplementationClass |
  UnexpectedConstructorCalldata`, or `UnknownClass`, plus the owner and
  guardian public keys and the address the fields fix. The fields are
  untrusted (usually an RPC response), so that address is what binds them to
  an account; a caller verifies by checking the address and the owner key.
  WASM exposes it as `inspectAccountDeployment`. The derive helpers answer
  "where would this key's account be" (discovery); the inspector and the
  guardian builder answer "is this known account mine" (verification).
- **Proxy targets are a third role.** An unupgraded Argent Cairo 0 account
  reports its *proxy* class hash on chain, not the class the proxy delegates
  to. Labelling those targets `Implementation` would have produced a signing
  allowlist that rejects valid Cairo 0 accounts while accepting hashes no RPC
  returns. The proxy is `Deployment` + `Implementation`; its targets are
  `ProxyTarget`, listed by `proxy_target_classes` and named as the values a
  template's `implementation` placeholder takes.
- **Decoding is exact.** `decode` validates every `Signer` variant's payload
  width (Starknet, Secp256k1 and EIP-191 one felt, Secp256r1 two, WebAuthn a
  length-prefixed origin plus four), the value ranges of the types behind them
  (`u128` limbs, 160-bit `EthAddress`, `u8` origin bytes, `NonZero` where
  Cairo requires it), and requires the trailing guardian option to consume the
  calldata exactly. Anything else is malformed, so the verdict never rests on
  a tag the constructor would have rejected.
- **Zero guardian.** A zero guardian means no guardian on every layout and
  yields the guardian-less calldata. v0.4.0+
  guardian keys are `NonZero`, so a literal `[0, owner, 0, 0, 0]` could never
  deploy; the builder never emits it and the decoder rejects it.
- **Discovery tables.** All candidate classes come from the registry
  (OpenZeppelin included, instead of a separate constant), so anything the
  inspector calls derivable is generated. Tables load once per scan. The
  default class leads each wallet type so the first candidate per type is
  unchanged from earlier releases.

Class hashes and roles, as published by the vendors:

| Family  | Class            | Role                        | Source                                              |
|---------|------------------|-----------------------------|-----------------------------------------------------|
| Braavos | `0x013bfe…8e6`   | deployment (base v1.0.0)    | braavos-account-cairo README @ v1.0.0               |
| Braavos | `0x03d16c…c201`  | deployment (base v1.1.0+)   | README @ v1.1.0, v1.2.0                             |
| Braavos | `0x00816d…6253`  | implementation v1.0.0       | README @ v1.0.0                                     |
| Braavos | `0x02c8c7…74bc`  | implementation v1.1.0       | README @ v1.1.0                                     |
| Braavos | `0x03957f…bf8a`  | implementation v1.2.0       | README @ v1.2.0                                     |
| Argent  | 0.5.0 / 0.4.0 / 0.3.1 / 0.3.0 | both           | argent-contracts-starknet `deployments/account.txt` |
| Argent  | Cairo 0 proxy / 0.2.4 … 0.2.1 | deployment / implementation | argent-x `starknet.constants.ts`      |

## Laws (tested)

1. Registry class hashes are unique; every entry has a role; `constructor` is
   `Some` iff the entry has the deployment role.
2. The issue's Mainnet account (`0x23e139…50fa`, owner `0x7829fd…2163`)
   equals `calculate_contract_address(pk, base_v1.0.0, [pk], 0)`, and no other
   Braavos class reproduces it. Its current class looks up as
   implementation-only and `try_with_class_hash` rejects it.
3. `generate_candidates` yields 16 candidates per index: 2 Braavos (one per
   base class), 4 Argent, 4 Argent legacy, 4 Argent Cairo 0, 2 OpenZeppelin.
   No implementation class is a candidate. The first candidate per wallet
   type equals the default preset's (or current base's) address.
4. `decode(constructor_calldata(pk)) == StarknetOwnerNoGuardian { pk }` and
   `decode(constructor_calldata_with_guardian(pk, g)) ==
   StarknetOwnerWithGuardian { pk, Some(g) }` for both layouts, the latter
   producing the Mainnet-observed `[0, pk, 0, 0, g]` / `[pk, g]`;
   `[0, pk, 0]` (the historical broken shape) and `[0, pk, 0, 0, 0]` (zero
   guardian key) are rejected, and a zero guardian builds the guardian-less
   calldata. Every published template renders, token by token, to exactly
   the builders' output.
5. `inspect_deployment` says `FromSeed` for the fixture's deploy fields and
   `NotFromSeed(ImplementationClass)` for its current class; a guardian gives
   `NotFromSeed(Guardian)` with both keys returned, and
   `calculate_address_with_guardian` reproduces that deployment's address
   while the guardian-less derivation does not. The inspected address of the
   issue's deploy fields is the real Mainnet account.
6. The gateway allowlist refuses a Braavos implementation class with or
   without `allow_unlisted_class_hash`, on its own, not only through class
   resolution.
7. `implementation_classes(Argent)` contains the Cairo 0 proxy and no proxy
   target, so a signing allowlist built from it accepts what an unupgraded
   Cairo 0 account reports.
8. A proxy pointing at an unknown implementation is
   `NotFromSeed(UnknownProxyImplementation)` with the proxy still reported,
   never `UnknownClass`, which is reserved for a class hash absent from the
   registry.

## Alternatives considered

- Restructure `getAccountClassHashes()` to carry roles: breaks every caller
  keyed on its shape. It keeps its shape, gains the missing Braavos entries
  under role-prefixed keys, corrects the Cairo 0 labels, and is documented as
  superseded by the registry.
- Change the Argent default to v0.5.0: changes `deriveArgentAccountAddress(pk)`
  for every caller; the on-chain vector pins v0.4.0. Rejected.
- Have the derive helpers infer guardians: impossible from a public key. The
  inspector takes the deploy fields instead, which a caller has once it finds
  the account by any other means.
- Accept unknown Braavos hashes in `deriveBraavosAccountAddress` as before:
  the class a caller reads from chain is always an implementation class, so
  an unknown hash fed there is wrong by construction. Rejected, matching the
  Argent precedent; `calculateContractAddress` remains for explicit derivation.

## Review follow-ups

Automated review on the PR raised six things, all taken:
the Cairo 0 proxy role above; the decoder's tag-only classification;
`UnknownClass` being returned with a known proxy attached, which made the WASM
output say `known: true` alongside `unknown_class`; and guidance that read a
guardian from the live account rather than the deploy transaction; the
decoder accepting in-range lengths with out-of-range values; and a changelog
edit that had duplicated the new entries into released sections. CodeQL's
hard-coded-salt alerts are addressed by deriving candidate salts from
`SaltPolicy` and moving test fixtures into their own modules, as
`crates/ffi/src/address.rs` already does.

## Surface and baselines

New WASM exports `getAccountClassRegistry`, `inspectAccountDeployment` and
`deriveArgentAccountAddressWithGuardian`;
`deriveBraavosAccountAddress` now fails for implementation and unknown class
hashes. `account_class.rs` ratchets down (520 → 504 lines) as Braavos moves
to `account_class/braavos.rs`, with the registry, constructor convention,
inspector, Argent decode and Cairo 0 table each in their own module under the
soft limit;
`generate_candidates` leaves the function-size baseline. No baseline grows,
and the registry and decoder keep their tests in sibling `tests.rs` files to
stay under the soft limit.
FFI is unchanged; a C/Swift/Dart registry surface is a follow-up.
