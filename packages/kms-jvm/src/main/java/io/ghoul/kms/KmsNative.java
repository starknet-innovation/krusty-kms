package io.ghoul.kms;

public final class KmsNative {
  static {
    System.loadLibrary("kms_jni");
  }

  private KmsNative() {}

  public static native int validateMnemonic(String phrase);
  public static native byte[] mnemonicToSeed(String phrase, String passphrase);
  public static native byte[] derivePrivateKey(String mnemonic, int index, int accountIndex, int coinType, String passphrase);
  public static native int coinTypeTongo();
  public static native int coinTypeStarknet();
  public static native int coinTypeTongoView();
  public static native int coinTypeNostr();
  public static native String errorMessage(int code);
}
