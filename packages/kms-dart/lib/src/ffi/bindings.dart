import 'dart:ffi';

import 'package:ffi/ffi.dart';

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

// Native function typedefs — account management
typedef _AccountCreateFromMnemonicC = Int32 Function(Pointer<Utf8> mnemonic,
    Uint32 index, Uint32 accountIndex, Pointer<KmsFelt> contractAddress,
    Pointer<Utf8> passphrase, Pointer<Uint64> outHandle);
typedef _AccountCreateFromMnemonicDart = int Function(Pointer<Utf8> mnemonic,
    int index, int accountIndex, Pointer<KmsFelt> contractAddress,
    Pointer<Utf8> passphrase, Pointer<Uint64> outHandle);

typedef _AccountCreateFromPrivateKeyC = Int32 Function(Pointer<KmsFelt> privateKey,
    Pointer<KmsFelt> contractAddress,
    Pointer<Uint64> outHandle);
typedef _AccountCreateFromPrivateKeyDart = int Function(Pointer<KmsFelt> privateKey,
    Pointer<KmsFelt> contractAddress,
    Pointer<Uint64> outHandle);

typedef _AccountGetStateC = Int32 Function(
    Uint64 handle, Pointer<KmsAccountState> outState);
typedef _AccountGetStateDart = int Function(
    int handle, Pointer<KmsAccountState> outState);

typedef _AccountUpdateStateC = Int32 Function(
    Uint64 handle, Pointer<KmsAccountState> state);
typedef _AccountUpdateStateDart = int Function(
    int handle, Pointer<KmsAccountState> state);

typedef _AccountDestroyC = Int32 Function(Uint64 handle);
typedef _AccountDestroyDart = int Function(int handle);

// Native function typedefs — proof generation
typedef _GenerateProofC = Int32 Function(Uint64 handle, Pointer<Utf8> paramsJson,
    Pointer<Uint8> out, Size outLen, Pointer<Size> outWritten);
typedef _GenerateProofDart = int Function(int handle, Pointer<Utf8> paramsJson,
    Pointer<Uint8> out, int outLen, Pointer<Size> outWritten);

// Native function typedefs — ElGamal
typedef _ElgamalEncryptC = Int32 Function(
    Pointer<KmsFelt> message, Pointer<KmsProjectivePoint> publicKey,
    Pointer<KmsFelt> random, Pointer<KmsFelt> prefix,
    Pointer<KmsProjectivePoint> outL, Pointer<KmsProjectivePoint> outR,
    Pointer<Uint8> outProofJson, Size outProofJsonLen,
    Pointer<Size> outProofJsonWritten);
typedef _ElgamalEncryptDart = int Function(
    Pointer<KmsFelt> message, Pointer<KmsProjectivePoint> publicKey,
    Pointer<KmsFelt> random, Pointer<KmsFelt> prefix,
    Pointer<KmsProjectivePoint> outL, Pointer<KmsProjectivePoint> outR,
    Pointer<Uint8> outProofJson, int outProofJsonLen,
    Pointer<Size> outProofJsonWritten);

typedef _ElgamalDecryptC = Int32 Function(
    Pointer<KmsProjectivePoint> ciphertextL,
    Pointer<KmsProjectivePoint> ciphertextR,
    Pointer<KmsFelt> privateKey,
    Pointer<KmsProjectivePoint> outPoint);
typedef _ElgamalDecryptDart = int Function(
    Pointer<KmsProjectivePoint> ciphertextL,
    Pointer<KmsProjectivePoint> ciphertextR,
    Pointer<KmsFelt> privateKey,
    Pointer<KmsProjectivePoint> outPoint);

// Native function typedefs — signing
typedef _StarkSignC = Int32 Function(Pointer<KmsFelt> hash,
    Pointer<KmsFelt> privateKey, Pointer<KmsFelt> outR, Pointer<KmsFelt> outS);
typedef _StarkSignDart = int Function(Pointer<KmsFelt> hash,
    Pointer<KmsFelt> privateKey, Pointer<KmsFelt> outR, Pointer<KmsFelt> outS);

typedef _EthSignC = Int32 Function(Pointer<KmsFelt> hash,
    Pointer<Uint8> ethPrivateKeyBytes, Pointer<KmsEthSignature> outSignature);
typedef _EthSignDart = int Function(Pointer<KmsFelt> hash,
    Pointer<Uint8> ethPrivateKeyBytes, Pointer<KmsEthSignature> outSignature);

// Native function typedefs — calldata encoding
typedef _EncodeCalldataC = Int32 Function(
    Pointer<Utf8> paramsJson, Pointer<Uint8> out, Size outLen,
    Pointer<Size> outWritten);
typedef _EncodeCalldataDart = int Function(
    Pointer<Utf8> paramsJson, Pointer<Uint8> out, int outLen,
    Pointer<Size> outWritten);

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
  late final _DeriveNostrPrivateKeyDart deriveNostrPrivateKey;
  late final _DeriveNostrKeypairDart deriveNostrKeypair;

  // Contract
  late final _CalculateContractAddressDart calculateContractAddress;
  late final _DeriveOzAccountAddressDart deriveOzAccountAddress;

  // Coin types
  late final _GetCoinTypeDart getCoinTypeTongo;
  late final _GetCoinTypeDart getCoinTypeStarknet;
  late final _GetCoinTypeDart getCoinTypeNostr;

  // Error
  late final _ErrorNameDart errorName;
  late final _ErrorMessageDart errorMessage;

  // Account management
  late final _AccountCreateFromMnemonicDart accountCreateFromMnemonic;
  late final _AccountCreateFromPrivateKeyDart accountCreateFromPrivateKey;
  late final _AccountGetStateDart accountGetState;
  late final _AccountUpdateStateDart accountUpdateState;
  late final _AccountDestroyDart accountDestroy;

  // Proof generation
  late final _GenerateProofDart generateFundProof;
  late final _GenerateProofDart generateTransferProof;
  late final _GenerateProofDart generateRolloverProof;
  late final _GenerateProofDart generateWithdrawProof;
  late final _GenerateProofDart generateRagequitProof;

  // ElGamal
  late final _ElgamalEncryptDart elgamalEncrypt;
  late final _ElgamalDecryptDart elgamalDecrypt;

  // Signing
  late final _StarkSignDart starkSign;
  late final _EthSignDart ethSign;

  // Calldata encoding
  late final _EncodeCalldataDart encodeErc20Approve;
  late final _EncodeCalldataDart encodeFundCalls;
  late final _EncodeCalldataDart encodeTransferCalls;
  late final _EncodeCalldataDart encodeRolloverCalls;
  late final _EncodeCalldataDart encodeWithdrawCalls;
  late final _EncodeCalldataDart encodeRagequitCalls;

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
    getCoinTypeNostr =
        lib.lookupFunction<_GetCoinTypeC, _GetCoinTypeDart>('kms_get_coin_type_nostr');

    // Error
    errorName = lib.lookupFunction<_ErrorNameC, _ErrorNameDart>('kms_error_name');
    errorMessage =
        lib.lookupFunction<_ErrorMessageC, _ErrorMessageDart>('kms_error_message');

    // Account management
    accountCreateFromMnemonic =
        lib.lookupFunction<_AccountCreateFromMnemonicC, _AccountCreateFromMnemonicDart>(
            'kms_account_create_from_mnemonic');
    accountCreateFromPrivateKey =
        lib.lookupFunction<_AccountCreateFromPrivateKeyC, _AccountCreateFromPrivateKeyDart>(
            'kms_account_create_from_private_key');
    accountGetState =
        lib.lookupFunction<_AccountGetStateC, _AccountGetStateDart>(
            'kms_account_get_state');
    accountUpdateState =
        lib.lookupFunction<_AccountUpdateStateC, _AccountUpdateStateDart>(
            'kms_account_update_state');
    accountDestroy =
        lib.lookupFunction<_AccountDestroyC, _AccountDestroyDart>(
            'kms_account_destroy');

    // Proof generation
    generateFundProof =
        lib.lookupFunction<_GenerateProofC, _GenerateProofDart>(
            'kms_generate_fund_proof');
    generateTransferProof =
        lib.lookupFunction<_GenerateProofC, _GenerateProofDart>(
            'kms_generate_transfer_proof');
    generateRolloverProof =
        lib.lookupFunction<_GenerateProofC, _GenerateProofDart>(
            'kms_generate_rollover_proof');
    generateWithdrawProof =
        lib.lookupFunction<_GenerateProofC, _GenerateProofDart>(
            'kms_generate_withdraw_proof');
    generateRagequitProof =
        lib.lookupFunction<_GenerateProofC, _GenerateProofDart>(
            'kms_generate_ragequit_proof');

    // ElGamal
    elgamalEncrypt =
        lib.lookupFunction<_ElgamalEncryptC, _ElgamalEncryptDart>(
            'kms_elgamal_encrypt');
    elgamalDecrypt =
        lib.lookupFunction<_ElgamalDecryptC, _ElgamalDecryptDart>(
            'kms_elgamal_decrypt');

    // Signing
    starkSign =
        lib.lookupFunction<_StarkSignC, _StarkSignDart>('kms_stark_sign');
    ethSign =
        lib.lookupFunction<_EthSignC, _EthSignDart>('kms_eth_sign');

    // Calldata encoding
    encodeErc20Approve =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_erc20_approve');
    encodeFundCalls =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_fund_calls');
    encodeTransferCalls =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_transfer_calls');
    encodeRolloverCalls =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_rollover_calls');
    encodeWithdrawCalls =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_withdraw_calls');
    encodeRagequitCalls =
        lib.lookupFunction<_EncodeCalldataC, _EncodeCalldataDart>(
            'kms_encode_ragequit_calls');
  }
}
