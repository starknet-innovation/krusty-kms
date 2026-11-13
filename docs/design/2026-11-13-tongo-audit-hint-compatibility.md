# Tongo audit hint compatibility

## Decision

Auditor-enabled operations emit the 64-byte AE hint format used by the pinned
`@fatsolutions/tongo-sdk` 1.3.2 auditor. The key is HKDF-SHA256 over the
uncompressed Stark ECDH point. Its salt is SHA256 of the eight-byte account
nonce followed by the point coordinates; its info is `tongo`, the 32-byte
Tongo address, and 27 zero bytes. XChaCha20-Poly1305 authenticates 44 random
bytes followed by the four-byte big-endian balance. The 16-byte tag completes
the 64-byte ciphertext.

The account nonce is the operation parameter, not the later nonce used by the
owner's balance hint. It must fit `u64`. The audited balance must fit `u32`, as
required by the pinned auditor. Both are checked before encryption. A larger
balance still works without an auditor, but an auditor-enabled operation fails
instead of emitting a hint that the auditor cannot read.

## API boundary

The existing context-free `encrypt_for_auditor` and `decrypt_as_auditor`
functions retain their legacy format to avoid silently changing their meaning
for downstream callers. They are deprecated. New context-aware functions take
the operation nonce and Tongo address explicitly; all SDK operations use them.
No existing public signature is removed. The SDK's `Audit` serialization stays
64 ciphertext bytes and 24 nonce bytes. Cairo calldata encodes the ciphertext
as a `u512` with the least-significant 128-bit limb first, and the nonce as
an unshifted 192-bit integer in a `u256`. The client event reader reverses
those steps when reconstructing bytes and rejects event limbs that exceed
their Cairo integer widths.

The change spans the SDK operation builders, common Cairo serializer, client
event decoder, and cross-SDK vectors because they all handle the same hint.
Splitting the wire-format update would leave an intermediate version that
emits or reconstructs bytes differently from the pinned auditor.

## Verification

Rust tests check zero and maximum supported balances, nonce overflow, and
nonce/address binding. An ignored synthetic vector generator emits hints from
fund, transfer (both audit records), withdraw, and ragequit. The cross-SDK CI
job decrypts all five with the pinned TypeScript auditor primitives. No live
chain state or deployed Cairo verifier is needed for this format check. The
same vectors are serialized to Cairo integer limbs and reconstructed by the
pinned `starknet.js` types before TypeScript decrypts them. A client test also
round-trips the audit field of an actual fund calldata builder through the
event hint parser.
