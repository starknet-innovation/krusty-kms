# Endpoint-safe `Tx` errors, panic-free public-key parsing, crates.io-only WASM toolchain

Date: 2026-11-04. Status: accepted. Origin: security findings
[#198](https://github.com/starknet-innovation/krusty-kms/issues/198),
[#199](https://github.com/starknet-innovation/krusty-kms/issues/199) and
[#200](https://github.com/starknet-innovation/krusty-kms/issues/200) against
`72df49a` (Krusty 0.15.0), all Medium.

## Problems

1. The 2026-09-02 provider-error redaction gave `gateway` and `client` a
   classifier that never embeds `reqwest::Error`'s `Display` (which names
   the full request URL, API key included). `krusty-kms-wallet-api` sits
   below `client` and never got it: `Tx::raw_receipt` formatted the raw
   `ProviderError`, and `observe_transaction` (behind `Tx::wait` and
   `Tx::receipt`) formatted both the receipt and the status error. `Tx` is
   what every `Wallet::execute` and `deploy_oz_account` returns, so any
   transport failure while polling a transaction copied the endpoint into
   `KmsError` text. The client's ERC-20 and staking read paths had the same
   `to_string()` pattern.
2. The three public-key parsers (`wasm::proof::parse_public_key`,
   `wasm::deserialize_public_key`, `ffi::proof::parse_public_key`) and
   `common::utils::parse_public_key_hex` checked that the string after `0x`
   was 128 *bytes* long and then sliced at byte offset 64. A 128-byte string
   whose multi-byte character straddles offset 64 passed the check and
   panicked on the slice. In `krusty-kms-wasm` a panic is a trap: the module
   is unusable until reload, and the input is the Tongo recipient or auditor
   key, which a dApp takes from an untrusted counterparty. The FFI copy was
   caught by `catch_unwind` and surfaced as `KMS_ERR_INTERNAL`.
3. `wasm-pack` 0.15.0 downloads a prebuilt `wasm-bindgen` CLI tarball from
   GitHub releases, with no checksum or signature, whenever no matching
   binary is on `PATH`, which is the case on hosted runners. That binary
   generates the JS glue and the final `.wasm` that `publish-npm.yml` ships
   with provenance, while the docs said release tooling is never downloaded
   prebuilt.

## Decisions

**One classifier, in `wallet-api`.** `provider_error_message` and
`rpc_error` move from `client::wallet::utils` to
`krusty_kms_wallet_api::provider_error` (public, re-exported at the crate
root). The behaviour is the one the 2026-09-02 note specifies: typed errors
keep their upstream text; `ProviderError::Other` is downcast to
`JsonRpcClientError<HttpTransportError>` and reduced to
`provider transport error: <kind>`. The `reqwest::Error` arm uses method
calls only, so `wallet-api` gains no `reqwest` dependency. `client` keeps a
`pub(crate) use` of both names, so its call sites and its tests (including
the real refused-connection test against `create_provider`) are unchanged.
`Tx::raw_receipt`, `observe_transaction`, `Erc20`'s three read paths and
`selector_fallback_error`, and `Staking`'s two read paths go through it;
`StakingError` keeps its variant and loses only the URL. The
workspace-excluded `controller` crate is not touched: it does not currently
resolve (`starknet-types-core` version conflict) and its error mapping is
over the `starknet` crate's `ProviderError`, a different type.

**One public-key parser, in `common`.** `parse_public_key_digits` (private)
checks that every byte is an ASCII hex digit, then that there are 128 of
them, and only then uses `split_at(64)`, which is provably on a char
boundary. `parse_public_key_hex` keeps its lenient prefix handling and
calls it. New `parse_prefixed_public_key_hex` requires `0x`/`0X` and does
not strip the SEC1 `04` tag; it is the format the WASM and C ABI boundaries
accept, and all three of their parsers now delegate to it. Their wrong-length
and non-hex error messages become the common ones (`Invalid public key
format: ...`); the off-curve message and the FFI error code are unchanged,
except that the non-ASCII input is now `KMS_ERR_INVALID_INPUT` instead of
`KMS_ERR_INTERNAL`. WASM policy, stated in the parser docs: every panic is a
trap, so validate before indexing.

**WASM toolchain from crates.io only.** `.github/scripts/install-wasm-bindgen-cli.sh`
reads the `wasm-bindgen` version from `Cargo.lock`, runs
`cargo install wasm-bindgen-cli --version <that> --locked`, and checks that
`wasm-bindgen --version` on `PATH` reports it. Deriving the version from the
lockfile, rather than pinning a second copy in the workflows, is what keeps
the CLI and the crate from drifting when Dependabot bumps `wasm-bindgen`.
Both `publish-npm.yml` jobs and the `rust.yml` wasm job run it after
`cargo install wasm-pack`, and `wasm-pack build` / `wasm-pack test` run with
`--mode no-install`, so any attempt to download a tool fails the job instead
of silently falling back. `tools/check.sh wasm` uses `--mode no-install`
when the `wasm-bindgen` on `PATH` reports the `Cargo.lock` version, fails
when `CI` is set and it does not, and otherwise prints a note and lets
wasm-pack download, so the local mode keeps working out of the box, including
right after a lockfile bump. `rust.yml` triggers on the installer script so a
change to it runs the wasm job. `wasm-opt` is already disabled in
`crates/wasm/Cargo.toml`, so no other prebuilt tool is involved. Both docs
that claimed release tooling is never downloaded prebuilt now describe this.

## Laws (tested)

1. For a provider whose every request is refused and whose URL path carries a
   fake key, `Tx::wait`, `Tx::receipt` and `Tx::raw_receipt` errors contain
   neither the key nor the port, and name the `connect` kind, while the
   upstream error text still contains the key (`wallet-api/src/tests.rs`).
2. The classifier maps a leaky `ProviderError::Other`, a JSON-RPC error, a
   batch error and an invalid-id error to fixed kinds, and leaves a typed
   `StarknetError` untouched (same file; the client's own tests still pass
   through the re-export).
3. `"0x" + "a"*63 + "é" + "a"*63` (128 bytes, 127 chars) is an
   `InvalidPublicKey` error from `parse_public_key_hex` and
   `parse_prefixed_public_key_hex`, an error from `deserializePublicKey` and
   `generateTransferProof` under `wasm-pack test --node`, and
   `KMS_ERR_INVALID_INPUT` from the FFI parser. Each test was run once against
   the reverted fix and fails (panics) there.
4. `parse_prefixed_public_key_hex` rejects a missing prefix, a SEC1 tag, 128
   non-hex ASCII characters and an empty payload with distinct messages.
5. `wasm-pack test --node --mode no-install` and
   `wasm-pack build --release --target web --mode no-install` succeed with
   the crates.io CLI on `PATH` and an empty `WASM_PACK_CACHE`, and the
   `binary_install` debug log shows no download (run locally on macOS;
   `cargo install wasm-bindgen-cli --version 0.2.127 --locked` succeeds, so
   the published crate carries a lockfile).

## Guardrail baselines

`crates/common/src/utils.rs` sat on the file-size baseline and could not
take the extra validation, so its inline tests moved to
`crates/common/src/utils/tests.rs` (a child of the module, following
`kms/src/keystore/tests/`). The baselines were regenerated: `utils.rs` drops
off the list, and `wasm/src/lib.rs`, `wasm/src/proof.rs` and `ffi/src/proof.rs`
shrink, so the ratchet only tightened.
