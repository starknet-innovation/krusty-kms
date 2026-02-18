export type Hex = `0x${string}`;

export type Felt = {
  bytes: Uint8Array;
};

export type ProjectivePoint = {
  x: Felt;
  y: Felt;
  z: Felt;
};

export type TongoKeyPair = {
  privateKey: Felt;
  publicKey: ProjectivePoint;
};

export type NostrKeyPair = {
  privateKey: Uint8Array;
  publicKeyXOnly: Uint8Array;
};

export type KmsApi = {
  generateMnemonic(wordCount: number): string;
  validateMnemonic(phrase: string): void;
  mnemonicToSeed(phrase: string, passphrase?: string): Uint8Array;
  derivePrivateKey(
    mnemonic: string,
    index: number,
    accountIndex: number,
    coinType: number,
    passphrase?: string,
  ): Felt;
  deriveKeypair(
    mnemonic: string,
    index: number,
    accountIndex: number,
    coinType: number,
    passphrase?: string,
  ): TongoKeyPair;
  deriveViewPrivateKey(
    mnemonic: string,
    index: number,
    accountIndex: number,
    passphrase?: string,
  ): Felt;
  deriveViewKeypair(
    mnemonic: string,
    index: number,
    accountIndex: number,
    passphrase?: string,
  ): TongoKeyPair;
  deriveNostrPrivateKey(
    mnemonic: string,
    index: number,
    accountIndex: number,
    passphrase?: string,
  ): Uint8Array;
  deriveNostrKeypair(
    mnemonic: string,
    index: number,
    accountIndex: number,
    passphrase?: string,
  ): NostrKeyPair;
  calculateContractAddress(
    salt: Felt,
    classHash: Felt,
    constructorCalldata: Felt[],
    deployer: Felt,
  ): Felt;
  deriveOzAccountAddress(publicKeyX: Felt, classHash: Felt, salt?: Felt): Felt;
  coinTypes(): {
    tongo: number;
    starknet: number;
    tongoView: number;
    nostr: number;
  };
};
