# Sign Nostr raw message bytes

Date: 2026-11-06. Status: proposed.

## Problem

`sign_nostr_message` used k256's `Signer::sign`, which first SHA-256 hashes its
input. The Rust API, WASM `signNostrMessage`, and gateway
`nostr_raw_message` call the input a raw message. A standard BIP-340 verifier
over the supplied bytes therefore rejects the signature. The existing Rust
test used k256's `Verifier::verify`, which applies the same pre-hash and hid
the mismatch.

## Decision

Use k256's `SigningKey::sign_raw(message, &[0u8; 32])`. This passes the
supplied bytes directly into BIP-340 nonce and challenge construction, with
the same deterministic auxiliary randomness as `sign_nostr_event_id`.
The WASM binding continues to hex-decode the message before calling the core
function. Nostr event callers should hash the canonical event to its 32-byte
id and use `signNostrEventId`.

## Compatibility and verification

This changes signatures for every raw-message caller, including the gateway.
It is released as a security fix in a 1.x minor, not a major: the previous
output did not meet the documented BIP-340 raw-message contract, and standard
verifiers rejected it, so no correct caller could depend on it. To recreate
an old signature, a caller can explicitly SHA-256 hash the bytes before
calling the corrected function. Export signatures and wire shapes stay the
same.

Core tests check raw verification, rejection by k256's pre-hashing verifier,
and equality with the official BIP-340 vector for a 32-byte message. A WASM
test checks that signing those same 32 decoded bytes matches
`signNostrEventId`. The canonical Rust and WASM checks cover the gateway and
other callers.
