package io.ghoul.kms;

public final class Kms {
  private Kms() {}

  private static void check(int code) {
    if (code != 0) {
      throw new KmsException(code);
    }
  }

  public static void validateMnemonic(String phrase) {
    check(KmsNative.validateMnemonic(phrase));
  }

  public static byte[] mnemonicToSeed(String phrase, String passphrase) {
    return KmsNative.mnemonicToSeed(phrase, passphrase);
  }

  public static byte[] derivePrivateKey(
      String mnemonic,
      int index,
      int accountIndex,
      int coinType,
      String passphrase
  ) {
    return KmsNative.derivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase);
  }

  public static int tongoCoinType() {
    return KmsNative.coinTypeTongo();
  }

  public static int starknetCoinType() {
    return KmsNative.coinTypeStarknet();
  }

  public static int tongoViewCoinType() {
    return KmsNative.coinTypeTongoView();
  }

  public static int nostrCoinType() {
    return KmsNative.coinTypeNostr();
  }
}
