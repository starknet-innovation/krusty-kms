package io.krustykms

fun coinTypes(): Map<String, Int> = mapOf(
  "tongo" to Kms.tongoCoinType(),
  "starknet" to Kms.starknetCoinType(),
  "tongoView" to Kms.tongoViewCoinType(),
  "nostr" to Kms.nostrCoinType(),
)

fun derivePrivateKey(
  mnemonic: String,
  index: Int,
  accountIndex: Int,
  coinType: Int,
  passphrase: String = "",
): ByteArray = Kms.derivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase)
