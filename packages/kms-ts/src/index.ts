import type { Felt, KmsApi, NostrKeyPair, TongoKeyPair } from "./types.js";
export type { Felt, Hex, KmsApi, NostrKeyPair, ProjectivePoint, TongoKeyPair } from "./types.js";

class KmsNotConfiguredError extends Error {
  constructor() {
    super("kms backend is not configured; install native or wasm backend first");
    this.name = "KmsNotConfiguredError";
  }
}

const defaultBackend: KmsApi = {
  generateMnemonic() {
    throw new KmsNotConfiguredError();
  },
  validateMnemonic() {
    throw new KmsNotConfiguredError();
  },
  mnemonicToSeed() {
    throw new KmsNotConfiguredError();
  },
  derivePrivateKey() {
    throw new KmsNotConfiguredError();
  },
  deriveKeypair() {
    throw new KmsNotConfiguredError();
  },
  deriveViewPrivateKey() {
    throw new KmsNotConfiguredError();
  },
  deriveViewKeypair() {
    throw new KmsNotConfiguredError();
  },
  deriveNostrPrivateKey() {
    throw new KmsNotConfiguredError();
  },
  deriveNostrKeypair() {
    throw new KmsNotConfiguredError();
  },
  calculateContractAddress() {
    throw new KmsNotConfiguredError();
  },
  deriveOzAccountAddress() {
    throw new KmsNotConfiguredError();
  },
  coinTypes() {
    return {
      tongo: 5454,
      starknet: 9004,
      tongoView: 5353,
      nostr: 1237,
    };
  },
};

let backend: KmsApi = defaultBackend;

export function setBackend(next: KmsApi): void {
  backend = next;
}

export function generateMnemonic(wordCount: number): string {
  return backend.generateMnemonic(wordCount);
}

export function validateMnemonic(phrase: string): void {
  backend.validateMnemonic(phrase);
}

export function mnemonicToSeed(phrase: string, passphrase?: string): Uint8Array {
  return backend.mnemonicToSeed(phrase, passphrase);
}

export function derivePrivateKey(
  mnemonic: string,
  index: number,
  accountIndex: number,
  coinType: number,
  passphrase?: string,
): Felt {
  return backend.derivePrivateKey(mnemonic, index, accountIndex, coinType, passphrase);
}

export function deriveKeypair(
  mnemonic: string,
  index: number,
  accountIndex: number,
  coinType: number,
  passphrase?: string,
): TongoKeyPair {
  return backend.deriveKeypair(mnemonic, index, accountIndex, coinType, passphrase);
}

export function deriveViewPrivateKey(
  mnemonic: string,
  index: number,
  accountIndex: number,
  passphrase?: string,
): Felt {
  return backend.deriveViewPrivateKey(mnemonic, index, accountIndex, passphrase);
}

export function deriveViewKeypair(
  mnemonic: string,
  index: number,
  accountIndex: number,
  passphrase?: string,
): TongoKeyPair {
  return backend.deriveViewKeypair(mnemonic, index, accountIndex, passphrase);
}

export function deriveNostrPrivateKey(
  mnemonic: string,
  index: number,
  accountIndex: number,
  passphrase?: string,
): Uint8Array {
  return backend.deriveNostrPrivateKey(mnemonic, index, accountIndex, passphrase);
}

export function deriveNostrKeypair(
  mnemonic: string,
  index: number,
  accountIndex: number,
  passphrase?: string,
): NostrKeyPair {
  return backend.deriveNostrKeypair(mnemonic, index, accountIndex, passphrase);
}

export function calculateContractAddress(
  salt: Felt,
  classHash: Felt,
  constructorCalldata: Felt[],
  deployer: Felt,
): Felt {
  return backend.calculateContractAddress(salt, classHash, constructorCalldata, deployer);
}

export function deriveOzAccountAddress(publicKeyX: Felt, classHash: Felt, salt?: Felt): Felt {
  return backend.deriveOzAccountAddress(publicKeyX, classHash, salt);
}

export function coinTypes() {
  return backend.coinTypes();
}
