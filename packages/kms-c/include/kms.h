#ifndef KRUSTY_KMS_H
#define KRUSTY_KMS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KMS_ABI_VERSION_MAJOR 1
#define KMS_ABI_VERSION_MINOR 0

#define KMS_OK 0
#define KMS_ERR_INVALID_HEX -1
#define KMS_ERR_INVALID_LENGTH -2
#define KMS_ERR_INVALID_MNEMONIC -3
#define KMS_ERR_INVALID_DERIVATION_PATH -4
#define KMS_ERR_NOT_IN_FIELD -5
#define KMS_ERR_POINT_AT_INFINITY -6
#define KMS_ERR_CRYPTO_FAILURE -7
#define KMS_ERR_BUFFER_TOO_SMALL -8
#define KMS_ERR_UNIMPLEMENTED -9
#define KMS_ERR_INTERNAL -10

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

int32_t kms_get_abi_version(uint32_t* major, uint32_t* minor);
int32_t kms_get_version_string(char* out, size_t out_len, size_t* out_written);

int32_t kms_felt_from_hex(const char* hex, KmsFelt* out);
int32_t kms_felt_to_hex(const KmsFelt* value, char* out, size_t out_len, size_t* out_written);
int32_t kms_felt_from_bytes_be(const uint8_t* bytes, size_t bytes_len, KmsFelt* out);
int32_t kms_felt_to_bytes_be(const KmsFelt* value, uint8_t* out, size_t out_len, size_t* out_written);

int32_t kms_projective_from_affine(const KmsAffinePoint* affine, KmsProjectivePoint* out);
int32_t kms_projective_to_affine(const KmsProjectivePoint* point, KmsAffinePoint* out);

int32_t kms_pedersen_hash(const KmsFelt* left, const KmsFelt* right, KmsFelt* out);
int32_t kms_poseidon_hash_many(const KmsFelt* values, size_t values_len, KmsFelt* out);

int32_t kms_generate_mnemonic(uint32_t word_count, char* out, size_t out_len, size_t* out_written);
int32_t kms_generate_mnemonic_from_entropy(const uint8_t* entropy, size_t entropy_len, char* out, size_t out_len, size_t* out_written);
int32_t kms_validate_mnemonic(const char* phrase);
int32_t kms_mnemonic_to_seed(const char* phrase, const char* passphrase, uint8_t* out, size_t out_len, size_t* out_written);

int32_t kms_derive_private_key_with_coin_type(const char* mnemonic, uint32_t index, uint32_t account_index, uint32_t coin_type, const char* passphrase, KmsFelt* out);
int32_t kms_derive_keypair_with_coin_type(const char* mnemonic, uint32_t index, uint32_t account_index, uint32_t coin_type, const char* passphrase, KmsTongoKeyPair* out);
int32_t kms_derive_view_private_key(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, KmsFelt* out);
int32_t kms_derive_view_keypair(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, KmsTongoKeyPair* out);
int32_t kms_derive_nostr_private_key(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, uint8_t out[32]);
int32_t kms_derive_nostr_keypair(const char* mnemonic, uint32_t index, uint32_t account_index, const char* passphrase, KmsNostrKeyPair* out);

int32_t kms_calculate_contract_address(const KmsFelt* salt, const KmsFelt* class_hash, const KmsFelt* constructor_calldata, size_t constructor_calldata_len, const KmsFelt* deployer_address, KmsFelt* out);
int32_t kms_derive_oz_account_address(const KmsFelt* public_key_x, const KmsFelt* class_hash, const KmsFelt* salt, KmsFelt* out);

uint32_t kms_get_coin_type_tongo(void);
uint32_t kms_get_coin_type_starknet(void);
uint32_t kms_get_coin_type_tongo_view(void);
uint32_t kms_get_coin_type_nostr(void);

const char* kms_error_name(int32_t code);
const char* kms_error_message(int32_t code);

#ifdef __cplusplus
}
#endif

#endif
