import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'ffi/bindings.dart';
import 'ffi/library.dart';
import 'ffi/types.dart' as c;
import 'types.dart';

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
        calloc.free(buf);
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

  String generateMnemonic(int wordCount) {
    return _dynamicString(
      (out, outLen, written) =>
          _bindings.generateMnemonic(wordCount, out, outLen, written),
    );
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
      calloc.free(pEntropy);
    }
  }

  void validateMnemonic(String phrase) {
    final pPhrase = phrase.toNativeUtf8(allocator: calloc);
    try {
      _check(_bindings.validateMnemonic(pPhrase.cast()));
    } finally {
      calloc.free(pPhrase);
    }
  }

  Uint8List mnemonicToSeed(String phrase, {String passphrase = ''}) {
    final pPhrase = phrase.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<Uint8>(64);
    final pWritten = calloc<Size>();
    try {
      _check(_bindings.mnemonicToSeed(
          pPhrase.cast(), pPassphrase.cast(), pOut, 64, pWritten));
      final len = pWritten.value;
      final result = Uint8List(len);
      for (var i = 0; i < len; i++) {
        result[i] = pOut[i];
      }
      return result;
    } finally {
      calloc.free(pPhrase);
      calloc.free(pPassphrase);
      calloc.free(pOut);
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
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.derivePrivateKeyWithCoinType(
          pMnemonic.cast(), index, accountIndex, coinType, pPassphrase.cast(), pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
    }
  }

  TongoKeyPair deriveKeypair(
    String mnemonic, {
    required int index,
    required int accountIndex,
    required int coinType,
    String passphrase = '',
  }) {
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsTongoKeyPair>();
    try {
      _check(_bindings.deriveKeypairWithCoinType(
          pMnemonic.cast(), index, accountIndex, coinType, pPassphrase.cast(), pOut));
      return TongoKeyPair(
        _feltFromC(pOut.ref.privateKey),
        _projectiveFromC(pOut.ref.publicKey),
      );
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
    }
  }

  Felt deriveViewPrivateKey(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsFelt>();
    try {
      _check(_bindings.deriveViewPrivateKey(
          pMnemonic.cast(), index, accountIndex, pPassphrase.cast(), pOut));
      return _feltFromC(pOut.ref);
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
    }
  }

  TongoKeyPair deriveViewKeypair(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsTongoKeyPair>();
    try {
      _check(_bindings.deriveViewKeypair(
          pMnemonic.cast(), index, accountIndex, pPassphrase.cast(), pOut));
      return TongoKeyPair(
        _feltFromC(pOut.ref.privateKey),
        _projectiveFromC(pOut.ref.publicKey),
      );
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
    }
  }

  Uint8List deriveNostrPrivateKey(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<Uint8>(32);
    try {
      _check(_bindings.deriveNostrPrivateKey(
          pMnemonic.cast(), index, accountIndex, pPassphrase.cast(), pOut));
      final result = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        result[i] = pOut[i];
      }
      return result;
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
    }
  }

  NostrKeyPair deriveNostrKeypair(
    String mnemonic, {
    required int index,
    required int accountIndex,
    String passphrase = '',
  }) {
    final pMnemonic = mnemonic.toNativeUtf8(allocator: calloc);
    final pPassphrase = passphrase.toNativeUtf8(allocator: calloc);
    final pOut = calloc<c.KmsNostrKeyPair>();
    try {
      _check(_bindings.deriveNostrKeypair(
          pMnemonic.cast(), index, accountIndex, pPassphrase.cast(), pOut));
      final privKey = Uint8List(32);
      final pubKey = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        privKey[i] = pOut.ref.privateKey[i];
        pubKey[i] = pOut.ref.publicKeyXonly[i];
      }
      return NostrKeyPair(privKey, pubKey);
    } finally {
      calloc.free(pMnemonic);
      calloc.free(pPassphrase);
      calloc.free(pOut);
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
        'tongo_view': _bindings.getCoinTypeTongoView(),
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
}
