class KmsException implements Exception {
  final int code;
  final String message;

  const KmsException(this.code, this.message);

  static const int ok = 0;
  static const int errInvalidHex = -1;
  static const int errInvalidLength = -2;
  static const int errInvalidMnemonic = -3;
  static const int errInvalidDerivationPath = -4;
  static const int errNotInField = -5;
  static const int errPointAtInfinity = -6;
  static const int errCryptoFailure = -7;
  static const int errBufferTooSmall = -8;
  static const int errUnimplemented = -9;
  static const int errInternal = -10;

  @override
  String toString() => 'KmsException($code): $message';
}
