/*
 * kms_mobile.h - minimal C ABI for the iOS and Android post-quantum signers.
 *
 * Deliberately separate from packages/kms-c/include/kms.h. That header exports
 * mnemonic handling, BIP-39 derivation, software Stark signing and Tongo proof
 * generation; a Rust staticlib retains every #[no_mangle] symbol it defines, so
 * linking it into a phone would place private-key derivation and software
 * signing inside a binary whose entire security story is that the key never
 * leaves the secure element.
 *
 * The rule this surface holds to: it only ever handles PUBLIC material. There is
 * no key generation and no signing here, and there will not be - the enclave
 * does both.
 *
 * Conventions
 * -----------
 * - Key material crosses as bytes + length, not hex. Callers hold Data and
 *   ByteArray; a hex round trip at an ABI boundary is somewhere to lose a
 *   leading zero.
 * - Felts come back as 0x-prefixed, 64-digit, zero-padded hex, always. A caller
 *   cannot receive a shorter spelling of the same value.
 * - String outputs use the two-call sizing pattern: pass out = NULL to learn the
 *   required length via out_written, then call again with a buffer of
 *   out_written + 1 bytes.
 * - Every function returns KMS_MOBILE_OK or a KMS_MOBILE_ERR_* code. Nothing
 *   allocates on the caller's behalf and nothing needs freeing.
 *
 * This header is hand-written and lives beside the crate that defines it rather
 * than being mirrored into packages/, so there is one copy to keep in step
 * instead of three.
 */

#ifndef KMS_MOBILE_H
#define KMS_MOBILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * Result codes
 * ------------------------------------------------------------------ */

#define KMS_MOBILE_OK 0
#define KMS_MOBILE_ERR_NULL_POINTER 1
#define KMS_MOBILE_ERR_INVALID_INPUT 2
#define KMS_MOBILE_ERR_BUFFER_TOO_SMALL 3
#define KMS_MOBILE_ERR_CRYPTO 4
#define KMS_MOBILE_ERR_INTERNAL 5
/* The signature is well-formed but does not verify against the given key. */
#define KMS_MOBILE_ERR_VERIFY_FAILED 6

/* ------------------------------------------------------------------ *
 * Sizes, fixed by FIPS 204 and by the Starknet felt encoding
 * ------------------------------------------------------------------ */

#define KMS_MOBILE_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define KMS_MOBILE_ML_DSA_65_SIGNATURE_BYTES 3309
#define KMS_MOBILE_MESSAGE_BYTES 32
/* 0x + 64 digits + NUL */
#define KMS_MOBILE_FELT_HEX_BYTES 67

/* ------------------------------------------------------------------ *
 * Versioning and diagnostics
 * ------------------------------------------------------------------ */

/* Major is bumped on any breaking change to this header. */
int32_t kms_mobile_abi_version(uint32_t *major, uint32_t *minor);

/* Static, process-lifetime description of a result code. Never NULL, never
 * freed by the caller. */
const char *kms_mobile_error_message(int32_t code);

/* ------------------------------------------------------------------ *
 * ML-DSA-65 public material
 * ------------------------------------------------------------------ */

/*
 * Poseidon commitment to the 925-felt packed form of an ML-DSA-65 public key.
 *
 * This is the account contract's entire constructor argument, and the value the
 * contract recomputes on chain from the key each transaction carries. It is NOT
 * a re-encoding of the public key: the packed form expands 32 bytes of rho into
 * the 7680-coefficient matrix A by SHAKE-128 rejection sampling, so it cannot be
 * derived without this function.
 *
 * public_key must be exactly KMS_MOBILE_ML_DSA_65_PUBLIC_KEY_BYTES. Android
 * Keystore returns an X.509 SubjectPublicKeyInfo wrapper (1974 bytes on a
 * Pixel 8 Pro) - unwrap to the raw key first, or this returns
 * KMS_MOBILE_ERR_INVALID_INPUT.
 */
int32_t kms_mobile_ml_dsa_key_commitment(const uint8_t *public_key,
                                        size_t public_key_len,
                                        char *out,
                                        size_t out_len,
                                        size_t *out_written);

/*
 * Counterfactual account address for an ML-DSA-65 public key.
 *
 * Equivalent to committing the key and then deriving the contract address from
 * (salt, class_hash, [commitment], deployer = 0).
 *
 * salt is a parameter rather than a baked constant on purpose: the wallet
 * currently deploys these accounts at salt 0x0 (ML_DSA_ADDRESS_SALT), and a
 * constant duplicated here would be a second source of truth able to drift
 * silently. class_hash and salt are 0x-prefixed hex felts.
 */
int32_t kms_mobile_ml_dsa_account_address(const uint8_t *public_key,
                                         size_t public_key_len,
                                         const char *class_hash,
                                         const char *salt,
                                         char *out,
                                         size_t out_len,
                                         size_t *out_written);

/*
 * Does a signature verify against a public key over a 32-byte message?
 *
 * Returns KMS_MOBILE_OK when valid and KMS_MOBILE_ERR_VERIFY_FAILED when not,
 * so callers branch on one value rather than interpret a boolean.
 *
 * This is the signer's own sanity check. A device that returns a signature over
 * a re-encoded key fails here immediately and locally, instead of surfacing
 * later as the wallet declining to broadcast for no visible reason.
 *
 * message is the transaction hash as KMS_MOBILE_MESSAGE_BYTES big-endian bytes -
 * the same bytes the enclave signs, with an empty FIPS 204 context.
 */
int32_t kms_mobile_ml_dsa_verify(const uint8_t *public_key,
                                size_t public_key_len,
                                const uint8_t *message,
                                size_t message_len,
                                const uint8_t *signature,
                                size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* KMS_MOBILE_H */
