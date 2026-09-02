# Design: a separate C ABI for the iOS and Android post-quantum signers

Date: 2026-09-01

## Problem

The post-quantum mobile signer holds an ML-DSA-65 key inside a Secure Enclave or
Android Keystore and releases only a signature. It needs three pieces of
off-chain maths it cannot compute itself:

1. the Poseidon commitment to the 925-felt packed key, which is the account
   contract's whole constructor argument;
2. the counterfactual account address that commitment implies, so the app can
   show the user *which account* a key signs for rather than an opaque label;
3. a check that a signature it just produced verifies against its own public key.

All three already exist in Rust — `krusty_kms_crypto::ml_dsa` and
`krusty_kms::calculate_contract_address` — and all three are reachable from
TypeScript through the WASM surface. None is reachable from C.

The obvious move is to add them to `packages/kms-c/include/kms.h` and reuse
`crates/ffi`. That is wrong, and not for size reasons.

## Why a separate crate

`crates/ffi` exports `kms_derive_private_key_with_coin_type`,
`kms_account_create_from_mnemonic`, `kms_mnemonic_to_seed` and `kms_stark_sign`,
among others. A Rust `staticlib` retains every `#[no_mangle]` symbol it defines,
so linking that crate into a phone binary would place **mnemonic-to-private-key
derivation and software signing inside an application whose entire security story
is that the key never leaves the secure element**. An attacker who reaches code
execution in that process would find a complete software signer waiting.

That is an attack-surface argument. The size argument is real but secondary: the
mobile shared library is 787 KB for `aarch64-linux-android`, against a canonical
ABI that also carries Tongo proof generation and ElGamal.

So: `crates/ffi-mobile`, package `krusty-kms-mobile-cabi`, library `kms_mobile`.
It holds to the rule the WASM ML-DSA exports already state — *it only ever
handles public material.* There is no key generation and no signing on this
surface, and there will not be.

## Interface

`crates/ffi-mobile/include/kms_mobile.h`, five functions, no struct types:

```c
int32_t kms_mobile_abi_version(uint32_t *major, uint32_t *minor);
const char *kms_mobile_error_message(int32_t code);

int32_t kms_mobile_ml_dsa_key_commitment(
    const uint8_t *public_key, size_t public_key_len,
    char *out, size_t out_len, size_t *out_written);

int32_t kms_mobile_ml_dsa_account_address(
    const uint8_t *public_key, size_t public_key_len,
    const char *class_hash, const char *salt,
    char *out, size_t out_len, size_t *out_written);

int32_t kms_mobile_ml_dsa_verify(
    const uint8_t *public_key, size_t public_key_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len);
```

Four deliberate departures from the canonical header:

- **Key material crosses as bytes, not hex.** The consumers hold `Data` and
  `ByteArray`; a hex round trip at an ABI boundary is somewhere to lose a leading
  zero. The canonical header speaks hex because its consumer is TypeScript.
- **Felts come back zero-padded to 64 digits, always**, so a caller cannot
  receive a shorter spelling of the same value. starknet.js returns the minimal
  spelling; the parity vector records both.
- **`salt` is a parameter, not a baked constant.** The wallet deploys these
  accounts at `ML_DSA_ADDRESS_SALT = 0x0`; duplicating that here would be a
  second source of truth able to drift silently.
- **Verify returns a result code, not a bool.** `KMS_MOBILE_ERR_VERIFY_FAILED`
  is distinguishable from a malformed input, so the caller branches on one value.

`crate-type = ["staticlib", "cdylib", "rlib"]`. staticlib for iOS, where
cinterop links a `.a` into the app binary — this is the reason the canonical
crate, which is `cdylib` only, cannot serve iOS at all. `rlib` so the crate's own
integration tests can link it.

## Android and iOS only

The `extern "C"` layer lives in `src/exports.rs` under

```rust
#![cfg(any(target_os = "android", target_os = "ios"))]
```

Nothing else consumes this ABI, and gating it means a desktop or CI build of the
workspace exports no symbols from this crate at all — verified: the host
`libkms_mobile.a` contains zero `kms_mobile_*` symbols, while the iOS and Android
artefacts contain exactly the five above and nothing else.

Everything that layer calls is ordinary Rust in `src/lib.rs`, so the logic is
unit-tested on the host, where those two targets cannot run. That split is the
only reason the gate is affordable.

## Distribution: the crate packages itself

`./crates/ffi-mobile/build-mobile.sh [all|android|ios]` produces everything a
consumer needs, under `crates/ffi-mobile/dist/` (git-ignored):

```
dist/include/kms_mobile.h                           the ABI, copied verbatim
dist/android/jniLibs/arm64-v8a/libkms_mobile.so     an APK's jniLibs layout
dist/ios/KmsMobile.xcframework                      ios-arm64 + ios-arm64-simulator
dist/BUILD-INFO.txt                                 version, git rev, host, date
```

The first version of this had the *consumer* cross-compile the crate: the mobile
app's Gradle build ran `cargo build` for three target triples, searched for an
NDK to find a linker, and assembled the archives itself. That works, and it is
the wrong place for all of it. A Gradle build has no business knowing that
`aarch64-apple-ios-sim` is where the simulator archive comes from, and every
other consumer would have had to rediscover the same three things.

So the crate exports artefacts rather than instructions:

- **The XCFramework replaces triples with platforms.** A consumer asks for
  `ios-arm64` or `ios-arm64-simulator` — names Apple defines — instead of
  mapping a Kotlin/Native target back onto a cargo triple. It carries a
  generated `module.modulemap`, so it is importable from Swift directly and not
  only through a cinterop `.def`.
- **The Android library ships in `jniLibs` layout**, so packaging it is a
  directory reference and not a copy task.
- **The NDK search and the linker override live here**, where the failure is
  legible: this script names the clang it wants and the API level it links
  against (`ANDROID_API_LEVEL`, default 31 — the artefact's floor, deliberately
  below the app's `minSdk` so this is not what decides it).
- **`BUILD-INFO.txt` answers "which krusty built this?"** A consumer holding
  only `dist/` cannot otherwise tell, and a `.so` older than its header is the
  failure it exists to catch.

### Which architectures

arm64 only by default, on both platforms. No x86_64 Android **phone** has shipped
since Intel's Atom era, a decade below the API 37 this signer requires, and an
Apple-silicon host runs an arm64 emulator.

x86_64 exists for the case that is not a phone:

```bash
ANDROID_ABIS="arm64-v8a x86_64" ./crates/ffi-mobile/build-mobile.sh android
```

That is the lane worth remembering, because the Android parity vector is still
unpinned and its home is an instrumented test — and CI runners are x86_64
essentially everywhere, where an arm64 emulator is software emulation and far too
slow to run one. It stays opt-in because it costs every other builder a second
`rustup target add` for a library they will never load.

The ABI set is decided **here and only here**: the consumer reads
`dist/android/jniLibs/` to choose what to package, so nothing downstream repeats
the list and nothing can silently drop a slice it was not told about. The script
clears that directory before each Android build, so an ABI removed from
`ANDROID_ABIS` stops being shipped instead of lingering as a stale library for
hardware no longer supported.

### Autonomous, but not manual

The first cut of this made the consumer run the script by hand, and that traded
one problem for another: the mobile app had previously rebuilt the ABI as a side
effect of building itself, and a krusty edit silently stopped reaching it.

The distinction that resolves it is *who knows how* versus *whether it is
automatic*. The consumer wires one task that invokes this script — scope
`android` or `ios` — declaring the crate's sources as its inputs and `dist/` as
its outputs, so Gradle rebuilds on a Rust change and skips otherwise. The app
still knows no triple, no NDK path and no slice name; it knows "ask krusty to
package itself". Verified: editing `src/lib.rs` and building the Android app
re-runs the script; building again does not.

`-Pkrusty.mobile.dist=<dir>` swaps that task for a no-op, because a prebuilt
bundle *is* the input — which is the case that keeps this a distribution rather
than a build-time coupling with extra steps.

## Verification

- 6 unit tests on the host, covering length and felt-format rejection. One pins
  the 1974-byte case specifically: that is what Android Keystore returns for an
  ML-DSA public key (X.509 `SubjectPublicKeyInfo`, a 22-byte wrapper around the
  raw 1952), and accepting it would produce a commitment for a key nobody holds.
- 4 integration tests in `tests/parity.rs` forming a **cross-implementation
  vector**. The fixture is the public half of `tasks/keys/key.json` from the
  ml-dsa-cairo repository; the expected address was produced by starknet.js
  calling `calculateContractAddressFromHash("0x0", CLASS_HASH, [COMMITMENT], 0)`,
  which is verbatim what `mlDsaAccountAddress` in mc-wallet calls. Two further
  tests assert the salt and class hash actually reach the derivation, since a
  parameter that is accepted and ignored would pass the first test and be wrong
  everywhere.
- Built for `aarch64-apple-ios`, `aarch64-apple-ios-sim` and
  `aarch64-linux-android`; symbol tables inspected on all three.

If the phone derived a different address from the wallet, the user would fund one
account and sign for another, and nothing would report it until a transaction
failed. That is what the parity vector exists to prevent, and it is why the
expected value comes from the other implementation rather than from this one.

## Alternatives considered: UniFFI

**There is no recorded reason this repository hand-writes its FFI.** `uniffi`,
`cbindgen` and binding generators generally appear nowhere in the tree, and the
C ABI predates `docs/design/`. The guardrail culture around it —
`check-ffi-surface.sh` comparing `packages/kms-c/include/kms.h` against three
mirrored copies plus a frozen snapshot — grew around a hand-written surface
rather than being chosen over a generated one. So this section records an
assessment, not a history.

For this surface, hand-writing was the smaller job, for three reasons:

1. **UniFFI does not produce a stable C ABI.** It produces a private scaffolding
   ABI plus generated bindings, and that scaffolding changes shape between
   UniFFI versions. This repository distributes a *frozen* header to npm
   (`packages/kms-c`), SwiftPM (`packages/kms-swift`) and the JVM
   (`packages/kms-jvm`), and guards it byte-for-byte. UniFFI could not replace
   `kms.h`; it would be a second, differently-shaped mechanism beside it.
2. **Upstream UniFFI cannot target Kotlin Multiplatform.** Its Kotlin backend is
   JVM/Android via JNA; iOS is served by generating *Swift*. The consumer here is
   Compose Multiplatform with one Kotlin API in `commonMain`, so upstream UniFFI
   would give Android Kotlin and iOS Swift — and then need a hand-written
   Swift-to-Kotlin bridge, which is the plumbing it was supposed to remove, moved
   somewhere else. Real KMP support (JVM *and* Kotlin/Native) exists only in
   Gobley, a third-party fork of a now-unmaintained project. That is a
   supply-chain decision for a cryptography library, not a build-tooling one.
3. **It would not change the crate split.** UniFFI exports scaffolding for
   everything in the declared interface, so the argument above — keep mnemonic
   derivation and software signing out of a phone binary — still forces a
   separate, narrow crate.

It is also worth being precise about what the hand-written work actually cost.
The bindings are small: a six-line cinterop `.def`, roughly forty lines of JNA
transcribed from this header, and the Kotlin `actual`s. The time went into
cross-compiling Rust and packaging the artefacts — cargo not being on Gradle's
PATH when launched from Xcode, locating the NDK linker, AGP 9 rejecting
`Provider`s in the SourceSet API. **UniFFI would have saved none of that**: it
generates bindings, not build integration.

*Would change if:* the surface grows structured types. Passing `SignEnvelope`,
`PairingOffer` and `SignResponse` as typed records instead of JSON strings is
exactly what UniFFI is good at, and it would delete the Kotlin CBOR
implementation and the `alwaysUseByteString` trap with it. At that point the
arithmetic flips — one hand-written function per envelope kind, in three
languages, is the drift this project already refuses elsewhere. Revisit when
Phase 3 (the envelope codec) is scheduled, and evaluate Gobley's maintenance
posture then rather than now.

## Not in this surface

- **Transaction-hash functions.** The next step, and what lets the phone prove a
  hash belongs to the transaction it displays rather than trusting the extension.
- **The envelope CBOR codec.** Would delete the Kotlin implementation and the
  `alwaysUseByteString` foot-gun with it.
- **SNIP-12 and calldata decoding**, so the phone can show the same review the
  extension does.
- **"Is the account deployed?"** — that is a JSON-RPC call, not cryptography. It
  belongs in the app, and giving a signer network access is a design decision
  about metadata leakage rather than plumbing.
