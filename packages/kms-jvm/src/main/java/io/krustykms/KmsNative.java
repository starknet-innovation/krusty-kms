package io.krustykms;

public final class KmsNative {
    static {
        System.loadLibrary("kms_jni");
    }

    private KmsNative() {}

    // Version / ABI
    public static native int[] getAbiVersion();
    public static native String getVersionString();

    // Felt ops
    public static native byte[] feltFromHex(String hex);
    public static native String feltToHex(byte[] value);
    public static native byte[] feltFromBytesBe(byte[] bytes);
    public static native byte[] feltToBytesBe(byte[] value);

    // Point ops
    public static native byte[] projectiveFromAffine(byte[] affineX, byte[] affineY);
    public static native byte[] projectiveToAffine(byte[] pointX, byte[] pointY, byte[] pointZ);

    // Hash
    public static native byte[] pedersenHash(byte[] left, byte[] right);
    public static native byte[] poseidonHashMany(byte[][] values);

    // Mnemonic
    public static native String generateMnemonic(int wordCount);
    public static native String generateMnemonicFromEntropy(byte[] entropy);
    public static native int validateMnemonic(String phrase);
    public static native byte[] mnemonicToSeed(String phrase, String passphrase);

    // Key derivation
    public static native byte[] derivePrivateKey(String mnemonic, int index, int accountIndex, int coinType, String passphrase);
    public static native byte[] deriveKeypair(String mnemonic, int index, int accountIndex, int coinType, String passphrase);
    public static native byte[] deriveNostrPrivateKey(String mnemonic, int index, int accountIndex, String passphrase);
    public static native byte[] deriveNostrKeypair(String mnemonic, int index, int accountIndex, String passphrase);

    // Address
    public static native byte[] calculateContractAddress(byte[] salt, byte[] classHash, byte[][] constructorCalldata, byte[] deployerAddress);
    public static native byte[] deriveOzAccountAddress(byte[] publicKeyX, byte[] classHash, byte[] salt);

    // Coin types
    public static native int coinTypeTongo();
    public static native int coinTypeStarknet();
    public static native int coinTypeNostr();

    // Error
    public static native String errorName(int code);
    public static native String errorMessage(int code);

    // Account management
    public static native long accountCreateFromMnemonic(String mnemonic, int index, int accountIndex, byte[] contractAddress, String passphrase);
    public static native long accountCreateFromPrivateKey(byte[] privateKey, byte[] contractAddress);
    public static native long[] accountGetState(long handle);
    public static native void accountUpdateState(long handle, long balanceLow, long balanceHigh, long pendingBalanceLow, long pendingBalanceHigh, long nonce);
    public static native void accountDestroy(long handle);

    // Proof generation
    public static native String generateFundProof(long handle, String paramsJson);
    public static native String generateTransferProof(long handle, String paramsJson);
    public static native String generateRolloverProof(long handle, String paramsJson);
    public static native String generateWithdrawProof(long handle, String paramsJson);
    public static native String generateRagequitProof(long handle, String paramsJson);

    // ElGamal
    public static native byte[][] elgamalEncrypt(byte[] message, byte[] pubX, byte[] pubY, byte[] pubZ, byte[] random, byte[] prefix);
    public static native byte[] elgamalDecrypt(byte[] ciphLX, byte[] ciphLY, byte[] ciphLZ, byte[] ciphRX, byte[] ciphRY, byte[] ciphRZ, byte[] privateKey);

    // Signing
    public static native byte[][] starkSign(byte[] hash, byte[] privateKey);
    public static native byte[][] ethSign(byte[] hash, byte[] ethPrivateKeyBytes);

    // Calldata encoding
    public static native String encodeErc20Approve(String paramsJson);
    public static native String encodeFundCalls(String paramsJson);
    public static native String encodeTransferCalls(String paramsJson);
    public static native String encodeRolloverCalls(String paramsJson);
    public static native String encodeWithdrawCalls(String paramsJson);
    public static native String encodeRagequitCalls(String paramsJson);
}
