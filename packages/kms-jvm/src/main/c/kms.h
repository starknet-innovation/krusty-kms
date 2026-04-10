#ifndef KRUSTY_KMS_H
#define KRUSTY_KMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ====================================================================== */
/* ABI version                                                             */
/* ====================================================================== */

#define KMS_ABI_VERSION_MAJOR 2
#define KMS_ABI_VERSION_MINOR 0

/* ====================================================================== */
/* Error codes (positive integers, matching Rust)                          */
/* ====================================================================== */

#define KMS_OK                  0
#define KMS_ERR_NULL_POINTER    1
#define KMS_ERR_INVALID_INPUT   2
#define KMS_ERR_BUFFER_TOO_SMALL 3
#define KMS_ERR_CRYPTO          4
#define KMS_ERR_INTERNAL        5
#define KMS_ERR_INVALID_HANDLE  6
#define KMS_ERR_JSON            7

/* ====================================================================== */
/* Types                                                                   */
/* ====================================================================== */

typedef struct {
  uint8_t bytes[32];
} KmsFelt;

typedef struct {
  KmsFelt x;
  KmsFelt y;
  KmsFelt z;
} KmsProjectivePoint;

typedef struct {
  KmsFelt x;
  KmsFelt y;
} KmsAffinePoint;

typedef struct {
  KmsFelt private_key;
  KmsProjectivePoint public_key;
} KmsTongoKeyPair;

typedef struct {
  uint8_t private_key[32];
  uint8_t public_key_xonly[32];
} KmsNostrKeyPair;

/** Opaque handle to a TongoAccount in the global registry. */
typedef uint64_t KmsAccountHandle;

/**
 * Account state exposed over the C ABI.
 * Balances are split into (low, high) u64 pairs: value = low + high * 2^64.
 */
typedef struct {
  uint64_t balance_low;
  uint64_t balance_high;
  uint64_t pending_balance_low;
  uint64_t pending_balance_high;
  uint64_t nonce;
} KmsAccountState;

/**
 * Secp256k1 ECDSA signature in the OZ 5-felt format:
 * [r_low, r_high, s_low, s_high, v]
 */
typedef struct {
  KmsFelt r_low;
  KmsFelt r_high;
  KmsFelt s_low;
  KmsFelt s_high;
  KmsFelt v;
} KmsEthSignature;

/* ====================================================================== */
/* Version / ABI                                                           */
/* ====================================================================== */

int32_t kms_get_abi_version(uint32_t* major, uint32_t* minor);
int32_t kms_get_version_string(char* out, size_t out_len, size_t* out_written);

/* ====================================================================== */
/* Felt ops                                                                */
/* ====================================================================== */

int32_t kms_felt_from_hex(const char* hex, KmsFelt* out);
int32_t kms_felt_to_hex(const KmsFelt* value, char* out, size_t out_len, size_t* out_written);
int32_t kms_felt_from_bytes_be(const uint8_t* bytes, size_t bytes_len, KmsFelt* out);
int32_t kms_felt_to_bytes_be(const KmsFelt* value, uint8_t* out, size_t out_len, size_t* out_written);

/* ====================================================================== */
/* Point ops                                                               */
/* ====================================================================== */

int32_t kms_projective_from_affine(const KmsAffinePoint* affine, KmsProjectivePoint* out);
int32_t kms_projective_to_affine(const KmsProjectivePoint* point, KmsAffinePoint* out);

/* ====================================================================== */
/* Hash                                                                    */
/* ====================================================================== */

int32_t kms_pedersen_hash(const KmsFelt* left, const KmsFelt* right, KmsFelt* out);
int32_t kms_poseidon_hash_many(const KmsFelt* values, size_t values_len, KmsFelt* out);

/* ====================================================================== */
/* Mnemonic                                                                */
/* ====================================================================== */

int32_t kms_generate_mnemonic(uint32_t word_count, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_mnemonic_from_entropy(const uint8_t* entropy, size_t entropy_len, char* out, size_t out_len, size_t* out_written);
int32_t kms_validate_mnemonic(const char* phrase);
int32_t kms_mnemonic_to_seed(const char* phrase, const char* passphrase, uint8_t* out, size_t out_len, size_t* out_written);

/* ====================================================================== */
/* Key derivation                                                          */
/* ====================================================================== */

int32_t kms_derive_private_key_with_coin_type(const char* mnemonic, uint32_t index, uint32_t account_index, uint32_t coin_type, const char* passphrase, KmsFelt* out);
int32_t kms_derive_keypair_with_coin_type(const char* mnemonic, uint32_t index, uint32_t account_index, uint32_t coin_type, const char* passphrase, KmsTongoKeyPair* out);
int32_t kms_derive_nostr_private_key(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, uint8_t out[32]);
int32_t kms_derive_nostr_keypair(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, KmsNostrKeyPair* out);

/* ====================================================================== */
/* Address                                                                 */
/* ====================================================================== */

int32_t kms_calculate_contract_address(const KmsFelt* salt, const KmsFelt* class_hash, const KmsFelt* constructor_calldata, size_t constructor_calldata_len, const KmsFelt* deployer_address, KmsFelt* out);
int32_t kms_derive_oz_account_address(const KmsFelt* public_key_x, const KmsFelt* class_hash, const KmsFelt* salt, KmsFelt* out);

/* ====================================================================== */
/* Coin types                                                              */
/* ====================================================================== */

uint32_t kms_get_coin_type_tongo(void);
uint32_t kms_get_coin_type_starknet(void);
uint32_t kms_get_coin_type_nostr(void);

/* ====================================================================== */
/* Error                                                                   */
/* ====================================================================== */

const char* kms_error_name(int32_t code);
const char* kms_error_message(int32_t code);

/* ====================================================================== */
/* Account management                                                      */
/* ====================================================================== */

int32_t kms_account_create_from_mnemonic(const char* mnemonic, uint32_t index, uint32_t account_index, const KmsFelt* contract_address, const char* passphrase, KmsAccountHandle* out_handle);
int32_t kms_account_create_from_private_key(const KmsFelt* private_key, const KmsFelt* contract_address, KmsAccountHandle* out_handle);
int32_t kms_account_get_state(KmsAccountHandle handle, KmsAccountState* out_state);
int32_t kms_account_update_state(KmsAccountHandle handle, const KmsAccountState* state);
int32_t kms_account_destroy(KmsAccountHandle handle);

/* ====================================================================== */
/* Proof generation (JSON in/out via two-call pattern)                     */
/* ====================================================================== */

int32_t kms_generate_fund_proof(KmsAccountHandle handle, const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_transfer_proof(KmsAccountHandle handle, const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_rollover_proof(KmsAccountHandle handle, const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_withdraw_proof(KmsAccountHandle handle, const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_ragequit_proof(KmsAccountHandle handle, const char* params_json, char* out, size_t out_len, size_t* out_written);

/* ====================================================================== */
/* ElGamal encrypt/decrypt                                                 */
/* ====================================================================== */

int32_t kms_elgamal_encrypt(const KmsFelt* message, const KmsProjectivePoint* public_key, const KmsFelt* random, const KmsFelt* prefix, KmsProjectivePoint* out_l, KmsProjectivePoint* out_r, char* out_proof_json, size_t out_proof_json_len, size_t* out_proof_json_written);
int32_t kms_elgamal_decrypt(const KmsProjectivePoint* ciphertext_l, const KmsProjectivePoint* ciphertext_r, const KmsFelt* private_key, KmsProjectivePoint* out_point);

/* ====================================================================== */
/* Signing                                                                 */
/* ====================================================================== */

int32_t kms_stark_sign(const KmsFelt* hash, const KmsFelt* private_key, KmsFelt* out_r, KmsFelt* out_s);
int32_t kms_eth_sign(const KmsFelt* hash, const uint8_t eth_private_key_bytes[32], KmsEthSignature* out_signature);

/* ====================================================================== */
/* Calldata encoding (JSON in/out via two-call pattern)                    */
/* ====================================================================== */

int32_t kms_encode_erc20_approve(const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_encode_fund_calls(const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_encode_transfer_calls(const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_encode_rollover_calls(const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_encode_withdraw_calls(const char* params_json, char* out, size_t out_len, size_t* out_written);
int32_t kms_encode_ragequit_calls(const char* params_json, char* out, size_t out_len, size_t* out_written);

#ifdef __cplusplus
}
#endif

#endif
