import 'dart:ffi';

import 'types.dart';

// Native function typedefs — version
typedef _GetAbiVersionC = Int32 Function(Pointer<Uint32> major, Pointer<Uint32> minor);
typedef _GetAbiVersionDart = int Function(Pointer<Uint32> major, Pointer<Uint32> minor);

typedef _GetVersionStringC = Int32 Function(
    Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _GetVersionStringDart = int Function(
    Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

// Native function typedefs — felt
typedef _FeltFromHexC = Int32 Function(Pointer<Utf8> hex, Pointer<KmsFelt> out);
typedef _FeltFromHexDart = int Function(Pointer<Utf8> hex, Pointer<KmsFelt> out);

typedef _FeltToHexC = Int32 Function(
    Pointer<KmsFelt> value, Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _FeltToHexDart = int Function(
    Pointer<KmsFelt> value, Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

typedef _FeltFromBytesBeC = Int32 Function(
    Pointer<Uint8> bytes, Size bytesLen, Pointer<KmsFelt> out);
typedef _FeltFromBytesBeDart = int Function(
    Pointer<Uint8> bytes, int bytesLen, Pointer<KmsFelt> out);

typedef _FeltToBytesBeC = Int32 Function(
    Pointer<KmsFelt> value, Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _FeltToBytesBeDart = int Function(
    Pointer<KmsFelt> value, Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

// Native function typedefs — point
typedef _ProjectiveFromAffineC = Int32 Function(
    Pointer<KmsAffinePoint> affine, Pointer<KmsProjectivePoint> out);
typedef _ProjectiveFromAffineDart = int Function(
    Pointer<KmsAffinePoint> affine, Pointer<KmsProjectivePoint> out);

typedef _ProjectiveToAffineC = Int32 Function(
    Pointer<KmsProjectivePoint> point, Pointer<KmsAffinePoint> out);
typedef _ProjectiveToAffineDart = int Function(
    Pointer<KmsProjectivePoint> point, Pointer<KmsAffinePoint> out);

// Native function typedefs — hash
typedef _PedersenHashC = Int32 Function(
    Pointer<KmsFelt> left, Pointer<KmsFelt> right, Pointer<KmsFelt> out);
typedef _PedersenHashDart = int Function(
    Pointer<KmsFelt> left, Pointer<KmsFelt> right, Pointer<KmsFelt> out);

typedef _PoseidonHashManyC = Int32 Function(
    Pointer<KmsFelt> values, Size valuesLen, Pointer<KmsFelt> out);
typedef _PoseidonHashManyDart = int Function(
    Pointer<KmsFelt> values, int valuesLen, Pointer<KmsFelt> out);

// Native function typedefs — mnemonic
typedef _GenerateMnemonicC = Int32 Function(
    Uint32 wordCount, Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _GenerateMnemonicDart = int Function(
    int wordCount, Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

typedef _GenerateMnemonicFromEntropyC = Int32 Function(Pointer<Uint8> entropy,
    Size entropyLen, Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _GenerateMnemonicFromEntropyDart = int Function(Pointer<Uint8> entropy,
    int entropyLen, Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

typedef _ValidateMnemonicC = Int32 Function(Pointer<Utf8> phrase);
typedef _ValidateMnemonicDart = int Function(Pointer<Utf8> phrase);

typedef _MnemonicToSeedC = Int32 Function(Pointer<Utf8> phrase, Pointer<Utf8> passphrase,
    Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _MnemonicToSeedDart = int Function(Pointer<Utf8> phrase, Pointer<Utf8> passphrase,
    Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

// Native function typedefs — derivation
typedef _DerivePrivateKeyWithCoinTypeC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Uint32 coinType, Pointer<Utf8> passphrase, Pointer<KmsFelt> out);
typedef _DerivePrivateKeyWithCoinTypeDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, int coinType, Pointer<Utf8> passphrase, Pointer<KmsFelt> out);

typedef _DeriveKeypairWithCoinTypeC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Uint32 coinType, Pointer<Utf8> passphrase,
    Pointer<KmsTongoKeyPair> out);
typedef _DeriveKeypairWithCoinTypeDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, int coinType, Pointer<Utf8> passphrase,
    Pointer<KmsTongoKeyPair> out);

typedef _DeriveViewPrivateKeyC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Pointer<Utf8> passphrase, Pointer<KmsFelt> out);
typedef _DeriveViewPrivateKeyDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, Pointer<Utf8> passphrase, Pointer<KmsFelt> out);

typedef _DeriveViewKeypairC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Pointer<Utf8> passphrase, Pointer<KmsTongoKeyPair> out);
typedef _DeriveViewKeypairDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, Pointer<Utf8> passphrase, Pointer<KmsTongoKeyPair> out);

typedef _DeriveNostrPrivateKeyC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Pointer<Utf8> passphrase, Pointer<Uint8> out);
typedef _DeriveNostrPrivateKeyDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, Pointer<Utf8> passphrase, Pointer<Uint8> out);

typedef _DeriveNostrKeypairC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Pointer<Utf8> passphrase, Pointer<KmsNostrKeyPair> out);
typedef _DeriveNostrKeypairDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, Pointer<Utf8> passphrase, Pointer<KmsNostrKeyPair> out);

// Native function typedefs — contract
typedef _CalculateContractAddressC = Int32 Function(
    Pointer<KmsFelt> salt,
    Pointer<KmsFelt> classHash,
    Pointer<KmsFelt> constructorCalldata,
    Size constructorCalldataLen,
    Pointer<KmsFelt> deployerAddress,
    Pointer<KmsFelt> out);
typedef _CalculateContractAddressDart = int Function(
    Pointer<KmsFelt> salt,
    Pointer<KmsFelt> classHash,
    Pointer<KmsFelt> constructorCalldata,
    int constructorCalldataLen,
    Pointer<KmsFelt> deployerAddress,
    Pointer<KmsFelt> out);

typedef _DeriveOzAccountAddressC = Int32 Function(Pointer<KmsFelt> publicKeyX,
    Pointer<KmsFelt> classHash, Pointer<KmsFelt> salt, Pointer<KmsFelt> out);
typedef _DeriveOzAccountAddressDart = int Function(Pointer<KmsFelt> publicKeyX,
    Pointer<KmsFelt> classHash, Pointer<KmsFelt> salt, Pointer<KmsFelt> out);

// Native function typedefs — coin types
typedef _GetCoinTypeC = Uint32 Function();
typedef _GetCoinTypeDart = int Function();

// Native function typedefs — error
typedef _ErrorNameC = Pointer<Utf8> Function(Int32 code);
typedef _ErrorNameDart = Pointer<Utf8> Function(int code);

typedef _ErrorMessageC = Pointer<Utf8> Function(Int32 code);
typedef _ErrorMessageDart = Pointer<Utf8> Function(int code);

class KmsBindings {
  // Version
  late final _GetAbiVersionDart getAbiVersion;
  late final _GetVersionStringDart getVersionString;

  // Felt
  late final _FeltFromHexDart feltFromHex;
  late final _FeltToHexDart feltToHex;
  late final _FeltFromBytesBeDart feltFromBytesBe;
  late final _FeltToBytesBeDart feltToBytesBe;

  // Point
  late final _ProjectiveFromAffineDart projectiveFromAffine;
  late final _ProjectiveToAffineDart projectiveToAffine;

  // Hash
  late final _PedersenHashDart pedersenHash;
  late final _PoseidonHashManyDart poseidonHashMany;

  // Mnemonic
  late final _GenerateMnemonicDart generateMnemonic;
  late final _GenerateMnemonicFromEntropyDart generateMnemonicFromEntropy;
  late final _ValidateMnemonicDart validateMnemonic;
  late final _MnemonicToSeedDart mnemonicToSeed;

  // Derivation
  late final _DerivePrivateKeyWithCoinTypeDart derivePrivateKeyWithCoinType;
  late final _DeriveKeypairWithCoinTypeDart deriveKeypairWithCoinType;
  late final _DeriveViewPrivateKeyDart deriveViewPrivateKey;
  late final _DeriveViewKeypairDart deriveViewKeypair;
  late final _DeriveNostrPrivateKeyDart deriveNostrPrivateKey;
  late final _DeriveNostrKeypairDart deriveNostrKeypair;

  // Contract
  late final _CalculateContractAddressDart calculateContractAddress;
  late final _DeriveOzAccountAddressDart deriveOzAccountAddress;

  // Coin types
  late final _GetCoinTypeDart getCoinTypeTongo;
  late final _GetCoinTypeDart getCoinTypeStarknet;
  late final _GetCoinTypeDart getCoinTypeTongoView;
  late final _GetCoinTypeDart getCoinTypeNostr;

  // Error
  late final _ErrorNameDart errorName;
  late final _ErrorMessageDart errorMessage;

  KmsBindings(DynamicLibrary lib) {
    // Version
    getAbiVersion =
        lib.lookupFunction<_GetAbiVersionC, _GetAbiVersionDart>('kms_get_abi_version');
    getVersionString = lib
        .lookupFunction<_GetVersionStringC, _GetVersionStringDart>('kms_get_version_string');

    // Felt
    feltFromHex =
        lib.lookupFunction<_FeltFromHexC, _FeltFromHexDart>('kms_felt_from_hex');
    feltToHex = lib.lookupFunction<_FeltToHexC, _FeltToHexDart>('kms_felt_to_hex');
    feltFromBytesBe =
        lib.lookupFunction<_FeltFromBytesBeC, _FeltFromBytesBeDart>('kms_felt_from_bytes_be');
    feltToBytesBe =
        lib.lookupFunction<_FeltToBytesBeC, _FeltToBytesBeDart>('kms_felt_to_bytes_be');

    // Point
    projectiveFromAffine =
        lib.lookupFunction<_ProjectiveFromAffineC, _ProjectiveFromAffineDart>(
            'kms_projective_from_affine');
    projectiveToAffine =
        lib.lookupFunction<_ProjectiveToAffineC, _ProjectiveToAffineDart>(
            'kms_projective_to_affine');

    // Hash
    pedersenHash =
        lib.lookupFunction<_PedersenHashC, _PedersenHashDart>('kms_pedersen_hash');
    poseidonHashMany =
        lib.lookupFunction<_PoseidonHashManyC, _PoseidonHashManyDart>('kms_poseidon_hash_many');

    // Mnemonic
    generateMnemonic = lib
        .lookupFunction<_GenerateMnemonicC, _GenerateMnemonicDart>('kms_generate_mnemonic');
    generateMnemonicFromEntropy =
        lib.lookupFunction<_GenerateMnemonicFromEntropyC, _GenerateMnemonicFromEntropyDart>(
            'kms_generate_mnemonic_from_entropy');
    validateMnemonic = lib
        .lookupFunction<_ValidateMnemonicC, _ValidateMnemonicDart>('kms_validate_mnemonic');
    mnemonicToSeed =
        lib.lookupFunction<_MnemonicToSeedC, _MnemonicToSeedDart>('kms_mnemonic_to_seed');

    // Derivation
    derivePrivateKeyWithCoinType =
        lib.lookupFunction<_DerivePrivateKeyWithCoinTypeC, _DerivePrivateKeyWithCoinTypeDart>(
            'kms_derive_private_key_with_coin_type');
    deriveKeypairWithCoinType =
        lib.lookupFunction<_DeriveKeypairWithCoinTypeC, _DeriveKeypairWithCoinTypeDart>(
            'kms_derive_keypair_with_coin_type');
    deriveViewPrivateKey =
        lib.lookupFunction<_DeriveViewPrivateKeyC, _DeriveViewPrivateKeyDart>(
            'kms_derive_view_private_key');
    deriveViewKeypair =
        lib.lookupFunction<_DeriveViewKeypairC, _DeriveViewKeypairDart>(
            'kms_derive_view_keypair');
    deriveNostrPrivateKey =
        lib.lookupFunction<_DeriveNostrPrivateKeyC, _DeriveNostrPrivateKeyDart>(
            'kms_derive_nostr_private_key');
    deriveNostrKeypair =
        lib.lookupFunction<_DeriveNostrKeypairC, _DeriveNostrKeypairDart>(
            'kms_derive_nostr_keypair');

    // Contract
    calculateContractAddress =
        lib.lookupFunction<_CalculateContractAddressC, _CalculateContractAddressDart>(
            'kms_calculate_contract_address');
    deriveOzAccountAddress =
        lib.lookupFunction<_DeriveOzAccountAddressC, _DeriveOzAccountAddressDart>(
            'kms_derive_oz_account_address');

    // Coin types
    getCoinTypeTongo =
        lib.lookupFunction<_GetCoinTypeC, _GetCoinTypeDart>('kms_get_coin_type_tongo');
    getCoinTypeStarknet =
        lib.lookupFunction<_GetCoinTypeC, _GetCoinTypeDart>('kms_get_coin_type_starknet');
    getCoinTypeTongoView =
        lib.lookupFunction<_GetCoinTypeC, _GetCoinTypeDart>('kms_get_coin_type_tongo_view');
    getCoinTypeNostr =
        lib.lookupFunction<_GetCoinTypeC, _GetCoinTypeDart>('kms_get_coin_type_nostr');

    // Error
    errorName = lib.lookupFunction<_ErrorNameC, _ErrorNameDart>('kms_error_name');
    errorMessage =
        lib.lookupFunction<_ErrorMessageC, _ErrorMessageDart>('kms_error_message');
  }
}
