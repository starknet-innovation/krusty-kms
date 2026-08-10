import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'ffi/bindings.dart';
import 'ffi/library.dart';
import 'ffi/types.dart' as c;
import 'types.dart';

typedef _ElgamalEncryptFn = int Function(
    Pointer<c.KmsFelt> message,
    Pointer<c.KmsProjectivePoint> publicKey,
    Pointer<c.KmsFelt> random,
    Pointer<c.KmsFelt> prefix,
    Pointer<c.KmsProjectivePoint> outL,
    Pointer<c.KmsProjectivePoint> outR,
    Pointer<Uint8> outProofJson,
    int outProofJsonLen,
    Pointer<Size> outProofJsonWritten);

class Kms {
  static Kms? _instance;
  late final KmsBindings _bindings;

  Kms._() {
    final lib = loadKmsLibrary();
    _bindings = KmsBindings(lib);
  }

  static Kms get instance => _instance ??= Kms._();

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  void _check(int code) {
    if (code == KmsException.ok) return;
    final msgPtr = _bindings.errorMessage(code);
    final msg = msgPtr.address == 0 ? 'unknown error' : msgPtr.toDartString();
    throw KmsException(code, msg);
  }

  /// Best-effort wipe of native secret bytes before [calloc.free].
  void _secureZero(Pointer<Uint8> ptr, int length) {
    if (ptr.address == 0 || length <= 0) return;
    for (var i = 0; i < length; i++) {
      ptr[i] = 0;
    }
  }

  void _secureFree(Pointer<NativeType> ptr, int lengthBytes) {
    if (ptr.address == 0) return;
    _secureZero(ptr.cast<Uint8>(), lengthBytes);
    calloc.free(ptr);
  }

  /// Allocate a NUL-terminated UTF-8 buffer and remember its full byte length
  /// (including terminator), so wipe covers embedded NULs in the payload.
  ({Pointer<Utf8> ptr, int byteLength}) _toNativeUtf8Secret(String value) {
    final ptr = value.toNativeUtf8(allocator: calloc);
    return (ptr: ptr, byteLength: _utf8ByteLength(value) + 1);
  }

  /// UTF-8 byte length of [value] without allocating a second secret copy.
  int _utf8ByteLength(String value) {
    var n = 0;
    for (final rune in value.runes) {
      if (rune <= 0x7F) {
        n += 1;
      } else if (rune <= 0x7FF) {
        n += 2;
      } else if (rune <= 0xFFFF) {
        n += 3;
      } else {
        n += 4;
      }
    }
    return n;
  }

  void _freeUtf8Secret(Pointer<Utf8> ptr, int byteLength) {
    if (ptr.address == 0) return;
    _secureFree(ptr, byteLength);
  }

  String _dynamicString(int Function(Pointer<Uint8> out, int outLen, Pointer<Size> written) fn) {
    final pWritten = calloc<Size>();
    try {
      _check(fn(nullptr, 0, pWritten));
      final len = pWritten.value;
      final buf = calloc<Uint8>(len + 1);
      try {
        _check(fn(buf, len + 1, pWritten));
        return buf.cast<Utf8>().toDartString(length: pWritten.value);
      } finally {
        _secureFree(buf, len + 1);
      }
    } finally {
      calloc.free(pWritten);
    }
  }

  // C <-> Dart struct conversions

  Pointer<c.KmsFelt> _feltToC(Felt value, Allocator allocator) {
    final ptr = allocator<c.KmsFelt>();
    for (var i = 0; i < 32; i++) {
      ptr.ref.bytes[i] = value.bytes[i];
    }
    return ptr;
  }

  Felt _feltFromC(c.KmsFelt cFelt) {
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = cFelt.bytes[i];
    }
    return Felt(bytes);
  }

  Pointer<c.KmsAffinePoint> _affineToC(AffinePoint point, Allocator allocator) {
    final ptr = allocator<c.KmsAffinePoint>();
    for (var i = 0; i < 32; i++) {
      ptr.ref.x.bytes[i] = point.x.bytes[i];
      ptr.ref.y.bytes[i] = point.y.bytes[i];
    }
    return ptr;
  }

  AffinePoint _affineFromC(c.KmsAffinePoint cPoint) {
    return AffinePoint(_feltFromC(cPoint.x), _feltFromC(cPoint.y));
  }

  Pointer<c.KmsProjectivePoint> _projectiveToC(
      ProjectivePoint point, Allocator allocator) {
    final ptr = allocator<c.KmsProjectivePoint>();
    for (var i = 0; i < 32; i++) {
      ptr.ref.x.bytes[i] = point.x.bytes[i];
      ptr.ref.y.bytes[i] = point.y.bytes[i];
      ptr.ref.z.bytes[i] = point.z.bytes[i];
    }
    return ptr;
  }

  ProjectivePoint _projectiveFromC(c.KmsProjectivePoint cPoint) {
    return ProjectivePoint(
      _feltFromC(cPoint.x),
      _feltFromC(cPoint.y),
      _feltFromC(cPoint.z),
    );
  }

  // ---------------------------------------------------------------------------
  // Version
  // ---------------------------------------------------------------------------

  (int, int) getAbiVersion() {
    final pMajor = calloc<Uint32>();
    final pMinor = calloc<Uint32>();
    try {
      _check(_bindings.getAbiVersion(pMajor, pMinor));
      return (pMajor.value, pMinor.value);
    } finally {
      calloc.free(pMajor);
      calloc.free(pMinor);
    }
  }

  String getVersionString() {
    return _dynamicString(_bindings.getVersionString);
  }

  // ---------------------------------------------------------------------------
  // Felt conversions
  // ---------------------------------------------------------------------------

  Felt feltFromHex(String hex) {
    final pHex = hex.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.feltFromHex(pHex.cast(), pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pHex);
      calloc.free(pOut);
    }
  }

  String feltToHex(Felt value) {
    final pFelt = _feltToC(value, calloc);
    try {
      return _dynamicString(
        (out, outLen, written) => _bindings.feltToHex(pFelt, out, outLen, written),
      );
    } finally {
      calloc.free(pFelt);
    }
  }

  Felt feltFromBytesBe(Uint8List data) {
    final pBytes = calloc<Uint8>(data.length);
    final pOut = calloc<c.KmsFelt>();
    try {
      for (var i = 0; i < data.length; i++) {
        pBytes[i] = data[i];
      }
      _check(_bindings.feltFromBytesBe(pBytes, data.length, pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pBytes);
      calloc.free(pOut);
    }
  }

  Uint8List feltToBytesBe(Felt value) {
    final pFelt = _feltToC(value, calloc);
    final pOut = calloc<Uint8>(32);
    final pWritten = calloc<Size>();
    try {
      _check(_bindings.feltToBytesBe(pFelt, pOut, 32, pWritten));
      final len = pWritten.value;
      final result = Uint8List(len);
      for (var i = 0; i < len; i++) {
        result[i] = pOut[i];
      }
      return result;
    } finally {
      calloc.free(pFelt);
      calloc.free(pOut);
      calloc.free(pWritten);
    }
  }

  // ---------------------------------------------------------------------------
  // Point conversions
  // ---------------------------------------------------------------------------

  ProjectivePoint projectiveFromAffine(AffinePoint affine) {
    final pAffine = _affineToC(affine, calloc);
    final pOut = calloc<c.KmsProjectivePoint>();
    try {
      _check(_bindings.projectiveFromAffine(pAffine, pOut));
      return _projectiveFromC(pOut.ref);
    } finally {
      calloc.free(pAffine);
      calloc.free(pOut);
    }
  }

  AffinePoint projectiveToAffine(ProjectivePoint point) {
    final pPoint = _projectiveToC(point, calloc);
    final pOut = calloc<c.KmsAffinePoint>();
    try {
      _check(_bindings.projectiveToAffine(pPoint, pOut));
      return _affineFromC(pOut.ref);
    } finally {
      calloc.free(pPoint);
      calloc.free(pOut);
    }
  }

  // ---------------------------------------------------------------------------
  // Hashing
  // ---------------------------------------------------------------------------

  Felt pedersenHash(Felt left, Felt right) {
    final pLeft = _feltToC(left, calloc);
    final pRight = _feltToC(right, calloc);
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.pedersenHash(pLeft, pRight, pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pLeft);
      calloc.free(pRight);
      calloc.free(pOut);
    }
  }

  Felt poseidonHashMany(List<Felt> values) {
    final pOut = calloc<c.KmsFelt>();
    Pointer<c.KmsFelt> pValues = nullptr;
    try {
      if (values.isNotEmpty) {
        pValues = calloc<c.KmsFelt>(values.length);
        for (var i = 0; i < values.length; i++) {
          for (var j = 0; j < 32; j++) {
            pValues[i].bytes[j] = values[i].bytes[j];
          }
        }
      }
      _check(_bindings.poseidonHashMany(pValues, values.length, pOut));
      return _feltFromC(pOut.ref);
    } finally {
      if (pValues.address != 0) calloc.free(pValues);
      calloc.free(pOut);
    }
  }

  // ---------------------------------------------------------------------------
  // Mnemonic
  // ---------------------------------------------------------------------------

  // C ABI `KMS_ERR_BUFFER_TOO_SMALL`
  static const int _errBufferTooSmall = 3;

  /// Random mnemonic generation: fixed capacity with grow-on-BUFFER_TOO_SMALL.
  ///
  /// Must not use the generic probe/fill helper — each `generateMnemonic` call
  /// produces a different phrase whose UTF-8 length can differ.
  String generateMnemonic(int wordCount) {
    var capacity = 512;
    final pWritten = calloc<Size>();
    try {
      for (var attempt = 0; attempt < 4; attempt++) {
        final allocCapacity = capacity;
        final buf = calloc<Uint8>(allocCapacity);
        try {
          pWritten.value = 0;
          final rc = _bindings.generateMnemonic(
              wordCount, buf, allocCapacity, pWritten);
          if (rc == KmsException.ok) {
            return buf.cast<Utf8>().toDartString(length: pWritten.value);
          }
          if (rc == _errBufferTooSmall && pWritten.value + 1 > allocCapacity) {
            capacity = pWritten.value + 1;
            continue;
          }
          _check(rc);
        } finally {
          _secureFree(buf, allocCapacity);
        }
      }
      throw const KmsException(
          KmsException.errInternal, 'mnemonic generation failed');
    } finally {
      calloc.free(pWritten);
    }
  }

  String generateMnemonicFromEntropy(Uint8List entropy) {
    final pEntropy = calloc<Uint8>(entropy.length);
    try {
      for (var i = 0; i < entropy.length; i++) {
        pEntropy[i] = entropy[i];
      }
      return _dynamicString(
        (out, outLen, written) => _bindings.generateMnemonicFromEntropy(
            pEntropy, entropy.length, out, outLen, written),
      );
    } finally {
      _secureFree(pEntropy, entropy.length);
    }
  }

  void validateMnemonic(String phrase) {
    final phraseNative = _toNativeUtf8Secret(phrase);
    try {
      _check(_bindings.validateMnemonic(phraseNative.ptr.cast()));
    } finally {
      _freeUtf8Secret(phraseNative.ptr, phraseNative.byteLength);
    }
  }

  Uint8List mnemonicToSeed(String phrase, {String passphrase = ''}) {
    final phraseNative = _toNativeUtf8Secret(phrase);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    final pOut = calloc<Uint8>(64);
    final pWritten = calloc<Size>();
    try {
      _check(_bindings.mnemonicToSeed(
          phraseNative.ptr.cast(), passphraseNative.ptr.cast(), pOut, 64, pWritten));
      final len = pWritten.value;
      final result = Uint8List(len);
      for (var i = 0; i < len; i++) {
        result[i] = pOut[i];
      }
      return result;
    } finally {
      _freeUtf8Secret(phraseNative.ptr, phraseNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      _secureFree(pOut, 64);
      calloc.free(pWritten);
    }
  }

  // ---------------------------------------------------------------------------
  // Key derivation
  // ---------------------------------------------------------------------------

  Felt derivePrivateKey(
    String mnemonic, {
    required int index,
    required int accountIndex,
    required int coinType,
    String passphrase = '',
  }) {
    final mnemonicNative = _toNativeUtf8Secret(mnemonic);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.derivePrivateKeyWithCoinType(
          mnemonicNative.ptr.cast(), index, accountIndex, coinType, passphraseNative.ptr.cast(), pOut));
      return _feltFromC(pOut.ref);
    } finally {
      _freeUtf8Secret(mnemonicNative.ptr, mnemonicNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      _secureFree(pOut, sizeOf<c.KmsFelt>());
    }
  }

  TongoKeyPair deriveKeypair(
    String mnemonic, {
    required int index,
    required int accountIndex,
    required int coinType,
    String passphrase = '',
  }) {
    final mnemonicNative = _toNativeUtf8Secret(mnemonic);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    final pOut = calloc<c.KmsTongoKeyPair>();
    try {
      _check(_bindings.deriveKeypairWithCoinType(
          mnemonicNative.ptr.cast(), index, accountIndex, coinType, passphraseNative.ptr.cast(), pOut));
      return TongoKeyPair(
        _feltFromC(pOut.ref.privateKey),
        _projectiveFromC(pOut.ref.publicKey),
      );
    } finally {
      _freeUtf8Secret(mnemonicNative.ptr, mnemonicNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      _secureFree(pOut, sizeOf<c.KmsTongoKeyPair>());
    }
  }

  Uint8List deriveNostrPrivateKey(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final mnemonicNative = _toNativeUtf8Secret(mnemonic);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    // ABI: kms_derive_nostr_private_key always writes exactly 32 bytes.
    final pOut = calloc<Uint8>(32);
    try {
      _check(_bindings.deriveNostrPrivateKey(
          mnemonicNative.ptr.cast(), index, accountIndex, passphraseNative.ptr.cast(), pOut));
      final result = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        result[i] = pOut[i];
      }
      return result;
    } finally {
      _freeUtf8Secret(mnemonicNative.ptr, mnemonicNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      _secureFree(pOut, 32);
    }
  }

  NostrKeyPair deriveNostrKeypair(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final mnemonicNative = _toNativeUtf8Secret(mnemonic);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    final pOut = calloc<c.KmsNostrKeyPair>();
    try {
      _check(_bindings.deriveNostrKeypair(
          mnemonicNative.ptr.cast(), index, accountIndex, passphraseNative.ptr.cast(), pOut));
      final privKey = Uint8List(32);
      final pubKey = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        privKey[i] = pOut.ref.privateKey[i];
        pubKey[i] = pOut.ref.publicKeyXonly[i];
      }
      return NostrKeyPair(privKey, pubKey);
    } finally {
      _freeUtf8Secret(mnemonicNative.ptr, mnemonicNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      _secureFree(pOut, sizeOf<c.KmsNostrKeyPair>());
    }
  }

  // ---------------------------------------------------------------------------
  // Contract
  // ---------------------------------------------------------------------------

  Felt calculateContractAddress(
    Felt salt,
    Felt classHash,
    List<Felt> constructorCalldata,
    Felt deployerAddress,
  ) {
    final pSalt = _feltToC(salt, calloc);
    final pClassHash = _feltToC(classHash, calloc);
    final pDeployer = _feltToC(deployerAddress, calloc);
    final pOut = calloc<c.KmsFelt>();
    Pointer<c.KmsFelt> pCalldata = nullptr;
    try {
      if (constructorCalldata.isNotEmpty) {
        pCalldata = calloc<c.KmsFelt>(constructorCalldata.length);
        for (var i = 0; i < constructorCalldata.length; i++) {
          for (var j = 0; j < 32; j++) {
            pCalldata[i].bytes[j] = constructorCalldata[i].bytes[j];
          }
        }
      }
      _check(_bindings.calculateContractAddress(
          pSalt, pClassHash, pCalldata, constructorCalldata.length, pDeployer, pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pSalt);
      calloc.free(pClassHash);
      calloc.free(pDeployer);
      calloc.free(pOut);
      if (pCalldata.address != 0) calloc.free(pCalldata);
    }
  }

  Felt deriveOzAccountAddress(Felt publicKeyX, Felt classHash, {Felt? salt}) {
    final pPubKey = _feltToC(publicKeyX, calloc);
    final pClassHash = _feltToC(classHash, calloc);
    final pSalt = salt != null ? _feltToC(salt, calloc) : nullptr.cast<c.KmsFelt>();
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.deriveOzAccountAddress(pPubKey, pClassHash, pSalt, pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pPubKey);
      calloc.free(pClassHash);
      if (salt != null) calloc.free(pSalt);
      calloc.free(pOut);
    }
  }

  // ---------------------------------------------------------------------------
  // Coin types
  // ---------------------------------------------------------------------------

  Map<String, int> get coinTypes => {
        'tongo': _bindings.getCoinTypeTongo(),
        'starknet': _bindings.getCoinTypeStarknet(),
        'nostr': _bindings.getCoinTypeNostr(),
      };

  // ---------------------------------------------------------------------------
  // Error info
  // ---------------------------------------------------------------------------

  String errorName(int code) {
    final ptr = _bindings.errorName(code);
    return ptr.address == 0 ? 'KMS_ERR_INTERNAL' : ptr.toDartString();
  }

  String errorMessage(int code) {
    final ptr = _bindings.errorMessage(code);
    return ptr.address == 0 ? 'unknown error' : ptr.toDartString();
  }

  // ---------------------------------------------------------------------------
  // Account management
  // ---------------------------------------------------------------------------

  AccountHandle accountCreateFromMnemonic(
    String mnemonic, {
    required int index,
    required int accountIndex,
    required Felt contractAddress,
    String passphrase = '',
  }) {
    final mnemonicNative = _toNativeUtf8Secret(mnemonic);
    final passphraseNative = _toNativeUtf8Secret(passphrase);
    final pAddr = _feltToC(contractAddress, calloc);
    final pHandle = calloc<Uint64>();
    try {
      _check(_bindings.accountCreateFromMnemonic(
          mnemonicNative.ptr.cast(), index, accountIndex, pAddr, passphraseNative.ptr.cast(), pHandle));
      return AccountHandle(pHandle.value);
    } finally {
      _freeUtf8Secret(mnemonicNative.ptr, mnemonicNative.byteLength);
      _freeUtf8Secret(passphraseNative.ptr, passphraseNative.byteLength);
      calloc.free(pAddr);
      calloc.free(pHandle);
    }
  }

  AccountHandle accountCreateFromPrivateKey(
    Felt privateKey,
    Felt contractAddress,
  ) {
    final pPrivateKey = _feltToC(privateKey, calloc);
    final pAddr = _feltToC(contractAddress, calloc);
    final pHandle = calloc<Uint64>();
    try {
      _check(_bindings.accountCreateFromPrivateKey(pPrivateKey, pAddr, pHandle));
      return AccountHandle(pHandle.value);
    } finally {
      _secureFree(pPrivateKey, sizeOf<c.KmsFelt>());
      calloc.free(pAddr);
      calloc.free(pHandle);
    }
  }

  AccountState accountGetState(AccountHandle handle) {
    final pState = calloc<c.KmsAccountState>();
    try {
      _check(_bindings.accountGetState(handle.rawValue, pState));
      return AccountState(
        balanceLow: pState.ref.balanceLow,
        balanceHigh: pState.ref.balanceHigh,
        pendingBalanceLow: pState.ref.pendingBalanceLow,
        pendingBalanceHigh: pState.ref.pendingBalanceHigh,
        nonce: pState.ref.nonce,
      );
    } finally {
      calloc.free(pState);
    }
  }

  void accountUpdateState(AccountHandle handle, AccountState state) {
    final pState = calloc<c.KmsAccountState>();
    try {
      pState.ref.balanceLow = state.balanceLow;
      pState.ref.balanceHigh = state.balanceHigh;
      pState.ref.pendingBalanceLow = state.pendingBalanceLow;
      pState.ref.pendingBalanceHigh = state.pendingBalanceHigh;
      pState.ref.nonce = state.nonce;
      _check(_bindings.accountUpdateState(handle.rawValue, pState));
    } finally {
      calloc.free(pState);
    }
  }

  void accountDestroy(AccountHandle handle) {
    _check(_bindings.accountDestroy(handle.rawValue));
  }

  // ---------------------------------------------------------------------------
  // Proof generation
  // ---------------------------------------------------------------------------

  String generateFundProof(AccountHandle handle, String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.generateFundProof(handle.rawValue, pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String generateTransferProof(AccountHandle handle, String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.generateTransferProof(handle.rawValue, pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String generateRolloverProof(AccountHandle handle, String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.generateRolloverProof(handle.rawValue, pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String generateWithdrawProof(AccountHandle handle, String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.generateWithdrawProof(handle.rawValue, pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String generateRagequitProof(AccountHandle handle, String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.generateRagequitProof(handle.rawValue, pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  // ---------------------------------------------------------------------------
  // ElGamal
  // ---------------------------------------------------------------------------

  /// Encrypts [message] with the legacy Fiat-Shamir transcript
  /// `H(prefix, L, R, AL)`, which does not bind the public key or the `AR`
  /// commitment. Only use this for verifiers pinned to the legacy transcript
  /// (e.g. deployed Cairo contracts); otherwise prefer [elgamalEncryptStrong].
  ({ProjectivePoint l, ProjectivePoint r, String proofJson}) elgamalEncrypt(
    Felt message,
    ProjectivePoint publicKey,
    Felt random,
    Felt prefix,
  ) =>
      _elgamalEncrypt(_bindings.elgamalEncrypt, message, publicKey, random, prefix);

  /// Encrypts [message] with the fully transcript-bound proof
  /// `H(prefix, pk, L, R, AL, AR)`. Rejected by legacy-transcript verifiers.
  ({ProjectivePoint l, ProjectivePoint r, String proofJson}) elgamalEncryptStrong(
    Felt message,
    ProjectivePoint publicKey,
    Felt random,
    Felt prefix,
  ) =>
      _elgamalEncrypt(
          _bindings.elgamalEncryptStrong, message, publicKey, random, prefix);

  ({ProjectivePoint l, ProjectivePoint r, String proofJson}) _elgamalEncrypt(
    _ElgamalEncryptFn encryptFn,
    Felt message,
    ProjectivePoint publicKey,
    Felt random,
    Felt prefix,
  ) {
    final pMsg = _feltToC(message, calloc);
    final pPub = _projectiveToC(publicKey, calloc);
    final pRand = _feltToC(random, calloc);
    final pPrefix = _feltToC(prefix, calloc);
    final pOutL = calloc<c.KmsProjectivePoint>();
    final pOutR = calloc<c.KmsProjectivePoint>();
    final pWritten = calloc<Size>();
    try {
      // First call to get proof size
      _check(encryptFn(
          pMsg, pPub, pRand, pPrefix, pOutL, pOutR, nullptr, 0, pWritten));
      final proofLen = pWritten.value;
      final pProof = calloc<Uint8>(proofLen + 1);
      try {
        _check(encryptFn(
            pMsg, pPub, pRand, pPrefix, pOutL, pOutR, pProof, proofLen + 1, pWritten));
        return (
          l: _projectiveFromC(pOutL.ref),
          r: _projectiveFromC(pOutR.ref),
          proofJson: pProof.cast<Utf8>().toDartString(length: pWritten.value),
        );
      } finally {
        calloc.free(pProof);
      }
    } finally {
      calloc.free(pMsg);
      calloc.free(pPub);
      _secureFree(pRand, sizeOf<c.KmsFelt>());
      calloc.free(pPrefix);
      calloc.free(pOutL);
      calloc.free(pOutR);
      calloc.free(pWritten);
    }
  }

  ProjectivePoint elgamalDecrypt(
    ProjectivePoint ciphertextL,
    ProjectivePoint ciphertextR,
    Felt privateKey,
  ) {
    final pL = _projectiveToC(ciphertextL, calloc);
    final pR = _projectiveToC(ciphertextR, calloc);
    final pKey = _feltToC(privateKey, calloc);
    final pOut = calloc<c.KmsProjectivePoint>();
    try {
      _check(_bindings.elgamalDecrypt(pL, pR, pKey, pOut));
      return _projectiveFromC(pOut.ref);
    } finally {
      calloc.free(pL);
      calloc.free(pR);
      _secureFree(pKey, sizeOf<c.KmsFelt>());
      calloc.free(pOut);
    }
  }

  // ---------------------------------------------------------------------------
  // Signing
  // ---------------------------------------------------------------------------

  ({Felt r, Felt s}) starkSign(Felt hash, Felt privateKey) {
    final pHash = _feltToC(hash, calloc);
    final pKey = _feltToC(privateKey, calloc);
    final pOutR = calloc<c.KmsFelt>();
    final pOutS = calloc<c.KmsFelt>();
    try {
      _check(_bindings.starkSign(pHash, pKey, pOutR, pOutS));
      return (r: _feltFromC(pOutR.ref), s: _feltFromC(pOutS.ref));
    } finally {
      calloc.free(pHash);
      _secureFree(pKey, sizeOf<c.KmsFelt>());
      calloc.free(pOutR);
      calloc.free(pOutS);
    }
  }

  EthSignature ethSign(Felt hash, Uint8List ethPrivateKeyBytes) {
    final pHash = _feltToC(hash, calloc);
    final pKey = calloc<Uint8>(32);
    final pOut = calloc<c.KmsEthSignature>();
    try {
      for (var i = 0; i < 32; i++) {
        pKey[i] = ethPrivateKeyBytes[i];
      }
      _check(_bindings.ethSign(pHash, pKey, pOut));
      return EthSignature(
        rLow: _feltFromC(pOut.ref.rLow),
        rHigh: _feltFromC(pOut.ref.rHigh),
        sLow: _feltFromC(pOut.ref.sLow),
        sHigh: _feltFromC(pOut.ref.sHigh),
        v: _feltFromC(pOut.ref.v),
      );
    } finally {
      calloc.free(pHash);
      _secureFree(pKey, 32);
      calloc.free(pOut);
    }
  }

  // ---------------------------------------------------------------------------
  // Calldata encoding
  // ---------------------------------------------------------------------------

  String encodeErc20Approve(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeErc20Approve(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String encodeFundCalls(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeFundCalls(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String encodeTransferCalls(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeTransferCalls(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String encodeRolloverCalls(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeRolloverCalls(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String encodeWithdrawCalls(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeWithdrawCalls(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }

  String encodeRagequitCalls(String paramsJson) {
    final pJson = paramsJson.toNativeUtf8(allocator: calloc);
    try {
      return _dynamicString(
        (out, outLen, written) =>
            _bindings.encodeRagequitCalls(pJson.cast(), out, outLen, written),
      );
    } finally {
      calloc.free(pJson);
    }
  }
}
