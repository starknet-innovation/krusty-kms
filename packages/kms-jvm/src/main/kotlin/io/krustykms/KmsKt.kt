package io.krustykms

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

fun abiVersion(): Pair<Int, Int> {
    val v = Kms.getAbiVersion()
    return Pair(v[0], v[1])
}

fun versionString(): String = Kms.getVersionString()

// ---------------------------------------------------------------------------
// Coin types
// ---------------------------------------------------------------------------

fun coinTypes(): Map<String, Int> = mapOf(
    "tongo" to Kms.tongoCoinType(),
    "starknet" to Kms.starknetCoinType(),
    "nostr" to Kms.nostrCoinType(),
)

// ---------------------------------------------------------------------------
// Key derivation (with defaults)
// ---------------------------------------------------------------------------

fun derivePrivateKey(
    mnemonic: String,
    index: Int,
    accountIndex: Int,
    coinType: Int,
    passphrase: String = "",
): Felt = Kms.derivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase)

fun deriveKeypair(
    mnemonic: String,
    index: Int,
    accountIndex: Int,
    coinType: Int,
    passphrase: String = "",
): TongoKeyPair = Kms.deriveKeypair(mnemonic, index, accountIndex, coinType, passphrase)

fun deriveNostrPrivateKey(
    mnemonic: String,
    index: Int,
    accountIndex: Int,
    passphrase: String = "",
): ByteArray = Kms.deriveNostrPrivateKey(mnemonic, index, accountIndex, passphrase)

fun deriveNostrKeypair(
    mnemonic: String,
    index: Int,
    accountIndex: Int,
    passphrase: String = "",
): NostrKeyPair = Kms.deriveNostrKeypair(mnemonic, index, accountIndex, passphrase)

// ---------------------------------------------------------------------------
// Account management (with defaults)
// ---------------------------------------------------------------------------

fun accountCreateFromMnemonic(
    mnemonic: String,
    index: Int,
    accountIndex: Int,
    contractAddress: Felt,
    passphrase: String = "",
): AccountHandle = Kms.accountCreateFromMnemonic(mnemonic, index, accountIndex, contractAddress, passphrase)

fun accountCreateFromPrivateKey(
    privateKey: Felt,
    contractAddress: Felt,
): AccountHandle = Kms.accountCreateFromPrivateKey(privateKey, contractAddress)

fun accountGetState(handle: AccountHandle): AccountState = Kms.accountGetState(handle)

fun accountUpdateState(handle: AccountHandle, state: AccountState) =
    Kms.accountUpdateState(handle, state)

fun accountDestroy(handle: AccountHandle) = Kms.accountDestroy(handle)

// ---------------------------------------------------------------------------
// Proof generation
// ---------------------------------------------------------------------------

fun generateFundProof(handle: AccountHandle, paramsJson: String): String =
    Kms.generateFundProof(handle, paramsJson)

fun generateTransferProof(handle: AccountHandle, paramsJson: String): String =
    Kms.generateTransferProof(handle, paramsJson)

fun generateRolloverProof(handle: AccountHandle, paramsJson: String): String =
    Kms.generateRolloverProof(handle, paramsJson)

fun generateWithdrawProof(handle: AccountHandle, paramsJson: String): String =
    Kms.generateWithdrawProof(handle, paramsJson)

fun generateRagequitProof(handle: AccountHandle, paramsJson: String): String =
    Kms.generateRagequitProof(handle, paramsJson)

// ---------------------------------------------------------------------------
// ElGamal
// ---------------------------------------------------------------------------

fun elgamalEncrypt(
    message: Felt,
    publicKey: ProjectivePoint,
    random: Felt,
    prefix: Felt,
): Kms.ElgamalEncryptResult = Kms.elgamalEncrypt(message, publicKey, random, prefix)

fun elgamalDecrypt(
    ciphertextL: ProjectivePoint,
    ciphertextR: ProjectivePoint,
    privateKey: Felt,
): ProjectivePoint = Kms.elgamalDecrypt(ciphertextL, ciphertextR, privateKey)

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

fun starkSign(hash: Felt, privateKey: Felt): Kms.StarkSignResult =
    Kms.starkSign(hash, privateKey)

fun ethSign(hash: Felt, ethPrivateKeyBytes: ByteArray): EthSignature =
    Kms.ethSign(hash, ethPrivateKeyBytes)

// ---------------------------------------------------------------------------
// Calldata encoding
// ---------------------------------------------------------------------------

fun encodeErc20Approve(paramsJson: String): String = Kms.encodeErc20Approve(paramsJson)
fun encodeFundCalls(paramsJson: String): String = Kms.encodeFundCalls(paramsJson)
fun encodeTransferCalls(paramsJson: String): String = Kms.encodeTransferCalls(paramsJson)
fun encodeRolloverCalls(paramsJson: String): String = Kms.encodeRolloverCalls(paramsJson)
fun encodeWithdrawCalls(paramsJson: String): String = Kms.encodeWithdrawCalls(paramsJson)
fun encodeRagequitCalls(paramsJson: String): String = Kms.encodeRagequitCalls(paramsJson)

// ---------------------------------------------------------------------------
// Address (with nullable salt)
// ---------------------------------------------------------------------------

fun deriveOzAccountAddress(
    publicKeyX: Felt,
    classHash: Felt,
    salt: Felt? = null,
): Felt = Kms.deriveOzAccountAddress(publicKeyX, classHash, salt)
