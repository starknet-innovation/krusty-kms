package io.krustykms;

public final class Kms {
    private Kms() {}

    private static void check(int code) {
        if (code != 0) {
            throw new KmsException(code);
        }
    }

    // ---------------------------------------------------------------------------
    // Version / ABI
    // ---------------------------------------------------------------------------

    public static int[] getAbiVersion() {
        return KmsNative.getAbiVersion();
    }

    public static String getVersionString() {
        return KmsNative.getVersionString();
    }

    // ---------------------------------------------------------------------------
    // Felt ops
    // ---------------------------------------------------------------------------

    public static Felt feltFromHex(String hex) {
        return new Felt(KmsNative.feltFromHex(hex));
    }

    public static String feltToHex(Felt value) {
        return KmsNative.feltToHex(value.bytes());
    }

    public static Felt feltFromBytesBe(byte[] bytes) {
        return new Felt(KmsNative.feltFromBytesBe(bytes));
    }

    public static byte[] feltToBytesBe(Felt value) {
        return KmsNative.feltToBytesBe(value.bytes());
    }

    // ---------------------------------------------------------------------------
    // Point ops
    // ---------------------------------------------------------------------------

    public static ProjectivePoint projectiveFromAffine(AffinePoint affine) {
        byte[] result = KmsNative.projectiveFromAffine(affine.x().bytes(), affine.y().bytes());
        return new ProjectivePoint(
            new Felt(copyRange(result, 0, 32)),
            new Felt(copyRange(result, 32, 64)),
            new Felt(copyRange(result, 64, 96))
        );
    }

    public static AffinePoint projectiveToAffine(ProjectivePoint point) {
        byte[] result = KmsNative.projectiveToAffine(
            point.x().bytes(), point.y().bytes(), point.z().bytes());
        return new AffinePoint(
            new Felt(copyRange(result, 0, 32)),
            new Felt(copyRange(result, 32, 64))
        );
    }

    // ---------------------------------------------------------------------------
    // Hash
    // ---------------------------------------------------------------------------

    public static Felt pedersenHash(Felt left, Felt right) {
        return new Felt(KmsNative.pedersenHash(left.bytes(), right.bytes()));
    }

    public static Felt poseidonHashMany(Felt[] values) {
        byte[][] raw = new byte[values.length][];
        for (int i = 0; i < values.length; i++) {
            raw[i] = values[i].bytes();
        }
        return new Felt(KmsNative.poseidonHashMany(raw));
    }

    // ---------------------------------------------------------------------------
    // Mnemonic
    // ---------------------------------------------------------------------------

    public static String generateMnemonic(int wordCount) {
        return KmsNative.generateMnemonic(wordCount);
    }

    public static String generateMnemonicFromEntropy(byte[] entropy) {
        return KmsNative.generateMnemonicFromEntropy(entropy);
    }

    public static void validateMnemonic(String phrase) {
        check(KmsNative.validateMnemonic(phrase));
    }

    public static byte[] mnemonicToSeed(String phrase, String passphrase) {
        return KmsNative.mnemonicToSeed(phrase, passphrase);
    }

    // ---------------------------------------------------------------------------
    // Key derivation
    // ---------------------------------------------------------------------------

    public static Felt derivePrivateKey(
            String mnemonic, int index, int accountIndex, int coinType, String passphrase) {
        return new Felt(KmsNative.derivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase));
    }

    public static TongoKeyPair deriveKeypair(
            String mnemonic, int index, int accountIndex, int coinType, String passphrase) {
        byte[] raw = KmsNative.deriveKeypair(mnemonic, index, accountIndex, coinType, passphrase);
        return tongoKeyPairFromBytes(raw);
    }

    public static byte[] deriveNostrPrivateKey(
            String mnemonic, int index, int accountIndex, String passphrase) {
        return KmsNative.deriveNostrPrivateKey(mnemonic, index, accountIndex, passphrase);
    }

    public static NostrKeyPair deriveNostrKeypair(
            String mnemonic, int index, int accountIndex, String passphrase) {
        byte[] raw = KmsNative.deriveNostrKeypair(mnemonic, index, accountIndex, passphrase);
        return new NostrKeyPair(copyRange(raw, 0, 32), copyRange(raw, 32, 64));
    }

    // ---------------------------------------------------------------------------
    // Address
    // ---------------------------------------------------------------------------

    public static Felt calculateContractAddress(
            Felt salt, Felt classHash, Felt[] constructorCalldata, Felt deployerAddress) {
        byte[][] calldataRaw = new byte[constructorCalldata.length][];
        for (int i = 0; i < constructorCalldata.length; i++) {
            calldataRaw[i] = constructorCalldata[i].bytes();
        }
        return new Felt(KmsNative.calculateContractAddress(
            salt.bytes(), classHash.bytes(), calldataRaw, deployerAddress.bytes()));
    }

    public static Felt deriveOzAccountAddress(Felt publicKeyX, Felt classHash, Felt salt) {
        return new Felt(KmsNative.deriveOzAccountAddress(
            publicKeyX.bytes(), classHash.bytes(), salt != null ? salt.bytes() : null));
    }

    // ---------------------------------------------------------------------------
    // Coin types
    // ---------------------------------------------------------------------------

    public static int tongoCoinType() {
        return KmsNative.coinTypeTongo();
    }

    public static int starknetCoinType() {
        return KmsNative.coinTypeStarknet();
    }

    public static int nostrCoinType() {
        return KmsNative.coinTypeNostr();
    }

    // ---------------------------------------------------------------------------
    // Error
    // ---------------------------------------------------------------------------

    public static String errorName(int code) {
        return KmsNative.errorName(code);
    }

    public static String errorMessage(int code) {
        return KmsNative.errorMessage(code);
    }

    // ---------------------------------------------------------------------------
    // Account management
    // ---------------------------------------------------------------------------

    public static AccountHandle accountCreateFromMnemonic(
            String mnemonic, int index, int accountIndex,
            Felt contractAddress, String passphrase) {
        long handle = KmsNative.accountCreateFromMnemonic(
            mnemonic, index, accountIndex, contractAddress.bytes(), passphrase);
        return new AccountHandle(handle);
    }

    public static AccountHandle accountCreateFromPrivateKey(
            Felt privateKey, Felt contractAddress) {
        long handle = KmsNative.accountCreateFromPrivateKey(
            privateKey.bytes(), contractAddress.bytes());
        return new AccountHandle(handle);
    }

    public static AccountState accountGetState(AccountHandle handle) {
        long[] state = KmsNative.accountGetState(handle.rawValue());
        return new AccountState(state[0], state[1], state[2], state[3], state[4]);
    }

    public static void accountUpdateState(AccountHandle handle, AccountState state) {
        KmsNative.accountUpdateState(handle.rawValue(),
            state.balanceLow(), state.balanceHigh(),
            state.pendingBalanceLow(), state.pendingBalanceHigh(),
            state.nonce());
    }

    public static void accountDestroy(AccountHandle handle) {
        KmsNative.accountDestroy(handle.rawValue());
    }

    // ---------------------------------------------------------------------------
    // Proof generation
    // ---------------------------------------------------------------------------

    public static String generateFundProof(AccountHandle handle, String paramsJson) {
        return KmsNative.generateFundProof(handle.rawValue(), paramsJson);
    }

    public static String generateTransferProof(AccountHandle handle, String paramsJson) {
        return KmsNative.generateTransferProof(handle.rawValue(), paramsJson);
    }

    public static String generateRolloverProof(AccountHandle handle, String paramsJson) {
        return KmsNative.generateRolloverProof(handle.rawValue(), paramsJson);
    }

    public static String generateWithdrawProof(AccountHandle handle, String paramsJson) {
        return KmsNative.generateWithdrawProof(handle.rawValue(), paramsJson);
    }

    public static String generateRagequitProof(AccountHandle handle, String paramsJson) {
        return KmsNative.generateRagequitProof(handle.rawValue(), paramsJson);
    }

    // ---------------------------------------------------------------------------
    // ElGamal
    // ---------------------------------------------------------------------------

    public static ElgamalEncryptResult elgamalEncrypt(
            Felt message, ProjectivePoint publicKey, Felt random, Felt prefix) {
        byte[][] result = KmsNative.elgamalEncrypt(
            message.bytes(),
            publicKey.x().bytes(), publicKey.y().bytes(), publicKey.z().bytes(),
            random.bytes(), prefix.bytes());
        // result[0..2] = outL (x,y,z), result[3..5] = outR (x,y,z), result[6] = proofJson bytes
        ProjectivePoint l = new ProjectivePoint(
            new Felt(result[0]), new Felt(result[1]), new Felt(result[2]));
        ProjectivePoint r = new ProjectivePoint(
            new Felt(result[3]), new Felt(result[4]), new Felt(result[5]));
        String proofJson = new String(result[6], java.nio.charset.StandardCharsets.UTF_8);
        return new ElgamalEncryptResult(l, r, proofJson);
    }

    public static ProjectivePoint elgamalDecrypt(
            ProjectivePoint ciphertextL, ProjectivePoint ciphertextR, Felt privateKey) {
        byte[] result = KmsNative.elgamalDecrypt(
            ciphertextL.x().bytes(), ciphertextL.y().bytes(), ciphertextL.z().bytes(),
            ciphertextR.x().bytes(), ciphertextR.y().bytes(), ciphertextR.z().bytes(),
            privateKey.bytes());
        return new ProjectivePoint(
            new Felt(copyRange(result, 0, 32)),
            new Felt(copyRange(result, 32, 64)),
            new Felt(copyRange(result, 64, 96))
        );
    }

    // ---------------------------------------------------------------------------
    // Signing
    // ---------------------------------------------------------------------------

    public static StarkSignResult starkSign(Felt hash, Felt privateKey) {
        byte[][] result = KmsNative.starkSign(hash.bytes(), privateKey.bytes());
        return new StarkSignResult(new Felt(result[0]), new Felt(result[1]));
    }

    public static EthSignature ethSign(Felt hash, byte[] ethPrivateKeyBytes) {
        byte[][] result = KmsNative.ethSign(hash.bytes(), ethPrivateKeyBytes);
        return new EthSignature(
            new Felt(result[0]), new Felt(result[1]),
            new Felt(result[2]), new Felt(result[3]),
            new Felt(result[4])
        );
    }

    // ---------------------------------------------------------------------------
    // Calldata encoding
    // ---------------------------------------------------------------------------

    public static String encodeErc20Approve(String paramsJson) {
        return KmsNative.encodeErc20Approve(paramsJson);
    }

    public static String encodeFundCalls(String paramsJson) {
        return KmsNative.encodeFundCalls(paramsJson);
    }

    public static String encodeTransferCalls(String paramsJson) {
        return KmsNative.encodeTransferCalls(paramsJson);
    }

    public static String encodeRolloverCalls(String paramsJson) {
        return KmsNative.encodeRolloverCalls(paramsJson);
    }

    public static String encodeWithdrawCalls(String paramsJson) {
        return KmsNative.encodeWithdrawCalls(paramsJson);
    }

    public static String encodeRagequitCalls(String paramsJson) {
        return KmsNative.encodeRagequitCalls(paramsJson);
    }

    // ---------------------------------------------------------------------------
    // Result types
    // ---------------------------------------------------------------------------

    public static final class ElgamalEncryptResult {
        private final ProjectivePoint l;
        private final ProjectivePoint r;
        private final String proofJson;

        public ElgamalEncryptResult(ProjectivePoint l, ProjectivePoint r, String proofJson) {
            this.l = l;
            this.r = r;
            this.proofJson = proofJson;
        }

        public ProjectivePoint l() { return l; }
        public ProjectivePoint r() { return r; }
        public String proofJson() { return proofJson; }
    }

    public static final class StarkSignResult {
        private final Felt r;
        private final Felt s;

        public StarkSignResult(Felt r, Felt s) {
            this.r = r;
            this.s = s;
        }

        public Felt r() { return r; }
        public Felt s() { return s; }
    }

    // ---------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------

    private static byte[] copyRange(byte[] src, int from, int to) {
        byte[] dest = new byte[to - from];
        System.arraycopy(src, from, dest, 0, dest.length);
        return dest;
    }

    private static TongoKeyPair tongoKeyPairFromBytes(byte[] raw) {
        // raw = 32 bytes private key + 96 bytes projective point (x, y, z)
        Felt privateKey = new Felt(copyRange(raw, 0, 32));
        ProjectivePoint publicKey = new ProjectivePoint(
            new Felt(copyRange(raw, 32, 64)),
            new Felt(copyRange(raw, 64, 96)),
            new Felt(copyRange(raw, 96, 128))
        );
        return new TongoKeyPair(privateKey, publicKey);
    }
}
