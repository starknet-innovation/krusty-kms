import 'dart:ffi';

final class KmsFelt extends Struct {
  @Array(32)
  external Array<Uint8> bytes;
}

final class KmsProjectivePoint extends Struct {
  external KmsFelt x;
  external KmsFelt y;
  external KmsFelt z;
}

final class KmsAffinePoint extends Struct {
  external KmsFelt x;
  external KmsFelt y;
}

final class KmsTongoKeyPair extends Struct {
  external KmsFelt privateKey;
  external KmsProjectivePoint publicKey;
}

final class KmsNostrKeyPair extends Struct {
  @Array(32)
  external Array<Uint8> privateKey;

  @Array(32)
  external Array<Uint8> publicKeyXonly;
}

final class KmsAccountState extends Struct {
  @Uint64()
  external int balanceLow;

  @Uint64()
  external int balanceHigh;

  @Uint64()
  external int pendingBalanceLow;

  @Uint64()
  external int pendingBalanceHigh;

  @Uint64()
  external int nonce;
}

final class KmsEthSignature extends Struct {
  external KmsFelt rLow;
  external KmsFelt rHigh;
  external KmsFelt sLow;
  external KmsFelt sHigh;
  external KmsFelt v;
}
