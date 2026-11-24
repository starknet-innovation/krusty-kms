# Restore the audit-hint nonce from Tongo events

Superseded for new Tongo hints by
[`2026-11-13-tongo-audit-hint-compatibility.md`](2026-11-13-tongo-audit-hint-compatibility.md).
The earlier encoder described here remains relevant to historical Krusty hints.

Date: 2026-11-05. Origin: security audit of `cb4f4ec` (Krusty 0.15.0).

## Problem

`serialize_ae_balance` places a 24-byte XChaCha20-Poly1305 nonce in a Cairo
`u256` as `nonce || 0^8`, then emits its `(low, high)` 128-bit limbs. The
client's event parser instead took 12 low bytes from each limb. A hint
serialized by this SDK therefore came back with a different nonce, causing
authenticated decryption to fail for ordinary events.

## Decision and invariant

Keep the encoder, which determines calldata already sent to contracts, and
make `parse_ae_balance` its inverse. The high limb contains `nonce[0..16]`;
the high eight bytes of the low limb contain `nonce[16..24]`. The low eight
bytes of the low limb are padding. Ciphertext parsing is unchanged.

For every 64-byte ciphertext and 24-byte nonce accepted by the encoder,
`parse_ae_balance(serialize_ae_balance(ciphertext, nonce))` returns the same
pair, including when the six felts start at a nonzero event-data offset.

The regression test covers distinct bytes across every limb, all-one bytes,
and all-zero bytes. It first failed on the old parser's nonce assertion while
the ciphertext assertion passed. No public API or on-chain format changes.
