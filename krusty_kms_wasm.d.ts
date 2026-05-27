/* tslint:disable */
/* eslint-disable */

/**
 * WASM-accessible Tongo account.
 *
 * Wraps the internal SDK account with JavaScript-friendly methods.
 * Handles key management and state tracking for confidential transactions.
 */
export class WasmAccount {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Get the contract address as hex string.
     */
    contractAddress(): string;
    /**
     * Decrypt an ElGamal ciphertext and recover the balance value.
     *
     * This performs full decryption including discrete log recovery using
     * brute force search. For large balances, this may be slow.
     *
     * # Arguments
     * * `ciphertext` - The ciphertext to decrypt
     * * `max_search` - Maximum value to search for (default: 1,000,000)
     *
     * # Returns
     * The decrypted balance as a string (for large number support in JS)
     */
    decryptBalance(ciphertext: WasmCiphertext, max_search?: bigint | null): string;
    /**
     * Decrypt an ElGamal ciphertext using the account key.
     *
     * Returns the decrypted point as `g^m`. The caller must perform discrete
     * log recovery to obtain the actual value `m`.
     *
     * # Arguments
     * * `ciphertext` - The ciphertext to decrypt
     *
     * # Returns
     * The decrypted point, including the identity point when the balance is zero
     */
    decryptToPoint(ciphertext: WasmCiphertext): WasmDecryptedPoint;
    /**
     * Create a new account from a BIP-39 mnemonic phrase.
     *
     * # Arguments
     * * `mnemonic` - 12 or 24 word BIP-39 mnemonic
     * * `address_index` - HD wallet address index (default: 0)
     * * `account_index` - HD wallet account index (default: 0)
     * * `contract_address` - Tongo contract address (hex string)
     * * `passphrase` - Optional BIP-39 passphrase
     *
     * # Returns
     * New WasmAccount instance or error
     */
    static fromMnemonic(mnemonic: string, address_index: number, account_index: number, contract_address: string, passphrase?: string | null): WasmAccount;
    /**
     * Create a new account from a private key.
     * # Arguments
     * * `private_key` - Private key as hex string (0x-prefixed)
     * * `contract_address` - Tongo contract address (hex string)
     */
    static fromPrivateKey(private_key: string, contract_address: string): WasmAccount;
    /**
     * Get current account state.
     */
    getState(): WasmAccountState;
    /**
     * Check if account has sufficient balance for an operation.
     */
    hasSufficientBalance(amount: string): boolean;
    /**
     * Get the owner (spending) public key as hex string.
     */
    ownerPublicKeyHex(): string;
    /**
     * Get total balance (available + pending).
     */
    totalBalance(): string;
    /**
     * Update account state from on-chain data.
     */
    updateState(state: WasmAccountState): void;
}

/**
 * Account state returned from on-chain queries.
 */
export class WasmAccountState {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create a new account state.
     */
    constructor(balance: string, pending_balance: string, nonce: bigint);
    /**
     * Get total balance (available + pending).
     */
    totalBalance(): string;
    /**
     * Available balance (can be spent immediately)
     */
    balance: string;
    /**
     * Current nonce for replay protection
     */
    nonce: bigint;
    /**
     * Pending balance (requires rollover to become available)
     */
    pending_balance: string;
}

/**
 * ElGamal ciphertext (L, R points).
 */
export class WasmCiphertext {
    free(): void;
    [Symbol.dispose](): void;
    constructor(l_x: string, l_y: string, r_x: string, r_y: string);
    l_x: string;
    l_y: string;
    r_x: string;
    r_y: string;
}

/**
 * Decrypted point result that can explicitly represent the identity point.
 */
export class WasmDecryptedPoint {
    free(): void;
    [Symbol.dispose](): void;
    constructor(is_identity: boolean, x?: string | null, y?: string | null);
    is_identity: boolean;
    get x(): string | undefined;
    set x(value: string | null | undefined);
    get y(): string | undefined;
    set y(value: string | null | undefined);
}

/**
 * Encrypted private key returned to JavaScript (all fields hex-encoded).
 */
export class WasmEncryptedKey {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     */
    encryptedKey: string;
    /**
     * Hex-encoded 24-byte nonce.
     */
    nonce: string;
    /**
     * Hex-encoded 16-byte salt.
     */
    salt: string;
}

/**
 * Encrypted payload returned to JavaScript (all fields hex-encoded).
 */
export class WasmEncryptedPayload {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     */
    ciphertext: string;
    /**
     * Hex-encoded 24-byte nonce.
     */
    nonce: string;
}

/**
 * Parameters for generating a fund proof.
 */
export class WasmFundParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(amount: string, nonce: string, chain_id: string, tongo_address: string, sender_address: string, current_cipher_l_x: string, current_cipher_l_y: string, current_cipher_r_x: string, current_cipher_r_y: string);
    withAuditor(auditor_public_key: string): WasmFundParams;
    /**
     * Amount to deposit (string for large numbers)
     */
    amount: string;
    /**
     * Optional auditor public key (hex, concatenated x||y)
     */
    get auditor_public_key(): string | undefined;
    /**
     * Optional auditor public key (hex, concatenated x||y)
     */
    set auditor_public_key(value: string | null | undefined);
    /**
     * Chain ID (hex)
     */
    chain_id: string;
    /**
     * Current balance ciphertext
     */
    current_cipher_l_x: string;
    current_cipher_l_y: string;
    current_cipher_r_x: string;
    current_cipher_r_y: string;
    /**
     * Transaction nonce (hex)
     */
    nonce: string;
    /**
     * Sender address (hex) - from get_caller_address()
     */
    sender_address: string;
    /**
     * Tongo contract address (hex)
     */
    tongo_address: string;
}

/**
 * Result of a fund proof generation.
 */
export class WasmFundProofResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Amount funded
     */
    amount: string;
    /**
     * Audit data as JSON (if auditor configured)
     */
    get audit_json(): string | undefined;
    /**
     * Audit data as JSON (if auditor configured)
     */
    set audit_json(value: string | null | undefined);
    /**
     * PoE proof as JSON
     */
    proof_json: string;
    /**
     * Public key Y point (x coordinate)
     */
    y_x: string;
    /**
     * Public key Y point (y coordinate)
     */
    y_y: string;
}

/**
 * Keypair for Tongo operations.
 */
export class WasmKeypair {
    free(): void;
    [Symbol.dispose](): void;
    constructor(private_key: string, public_key_x: string, public_key_y: string);
    /**
     * Get the full public key as "0x{x}{y}" concatenated hex.
     */
    publicKeyHex(): string;
    /**
     * Private key as hex string (0x-prefixed)
     */
    private_key: string;
    /**
     * Public key X coordinate as hex string
     */
    public_key_x: string;
    /**
     * Public key Y coordinate as hex string
     */
    public_key_y: string;
}

/**
 * Nostr keypair (secp256k1, x-only public key).
 *
 * Used for NIP-04/NIP-44 encrypted messaging.
 * Public key is x-only (32 bytes, BIP-340 format).
 */
export class WasmNostrKeypair {
    free(): void;
    [Symbol.dispose](): void;
    constructor(private_key: string, public_key: string);
    /**
     * Private key as hex string (64 hex chars, no 0x prefix)
     */
    private_key: string;
    /**
     * Public key as x-only hex string (64 hex chars, no 0x prefix)
     */
    public_key: string;
}

/**
 * Nostr BIP-340 Schnorr signature result.
 */
export class WasmNostrSignature {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * x-only public key (64 hex chars, no 0x prefix)
     */
    publicKey: string;
    /**
     * BIP-340 signature (128 hex chars, no 0x prefix)
     */
    signature: string;
}

/**
 * Point on the Stark curve (serialized as hex strings).
 */
export class WasmPoint {
    free(): void;
    [Symbol.dispose](): void;
    constructor(x: string, y: string);
    x: string;
    y: string;
}

/**
 * Parameters for generating a ragequit proof.
 */
export class WasmRagequitParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(recipient_address: string, nonce: string, chain_id: string, tongo_address: string, sender_address: string, current_cipher_l_x: string, current_cipher_l_y: string, current_cipher_r_x: string, current_cipher_r_y: string);
    withAuditor(auditor_public_key: string): WasmRagequitParams;
    /**
     * Optional auditor public key
     */
    get auditor_public_key(): string | undefined;
    /**
     * Optional auditor public key
     */
    set auditor_public_key(value: string | null | undefined);
    /**
     * Chain ID (hex)
     */
    chain_id: string;
    /**
     * Current balance ciphertext
     */
    current_cipher_l_x: string;
    current_cipher_l_y: string;
    current_cipher_r_x: string;
    current_cipher_r_y: string;
    /**
     * Transaction nonce (hex)
     */
    nonce: string;
    /**
     * Recipient address for withdrawn funds (hex)
     */
    recipient_address: string;
    /**
     * Sender address (hex)
     */
    sender_address: string;
    /**
     * Tongo contract address (hex)
     */
    tongo_address: string;
}

/**
 * Result of a ragequit proof generation.
 */
export class WasmRagequitProofResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Commitment A_r = R0^kx
     */
    a_r_x: string;
    a_r_y: string;
    /**
     * Commitment A_x = g^kx
     */
    a_x_x: string;
    a_x_y: string;
    /**
     * Full balance amount
     */
    amount: string;
    /**
     * Audit data as JSON (if auditor configured)
     */
    get audit_json(): string | undefined;
    /**
     * Audit data as JSON (if auditor configured)
     */
    set audit_json(value: string | null | undefined);
    /**
     * Recipient address
     */
    recipient: string;
    /**
     * Scalar response sx
     */
    sx: string;
    /**
     * Public key Y point
     */
    y_x: string;
    y_y: string;
}

/**
 * Parameters for generating a rollover proof.
 */
export class WasmRolloverParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(nonce: string, chain_id: string, tongo_address: string, sender_address: string);
    /**
     * Chain ID (hex)
     */
    chain_id: string;
    /**
     * Transaction nonce (hex)
     */
    nonce: string;
    /**
     * Sender address (hex)
     */
    sender_address: string;
    /**
     * Tongo contract address (hex)
     */
    tongo_address: string;
}

/**
 * Result of a rollover proof generation.
 */
export class WasmRolloverProofResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Pending amount that was rolled over
     */
    pending_amount: string;
    /**
     * PoE proof as JSON
     */
    proof_json: string;
    /**
     * Public key Y point
     */
    y_x: string;
    y_y: string;
}

/**
 * Stark ECDSA signature result.
 */
export class WasmStarkSignature {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Public key (hex)
     */
    publicKey: string;
    /**
     * Signature r component (hex)
     */
    r: string;
    /**
     * Signature s component (hex)
     */
    s: string;
}

/**
 * Parameters for generating a transfer proof.
 */
export class WasmTransferParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(recipient_public_key: string, amount: string, nonce: string, chain_id: string, tongo_address: string, sender_address: string, current_cipher_l_x: string, current_cipher_l_y: string, current_cipher_r_x: string, current_cipher_r_y: string);
    withAuditor(auditor_public_key: string): WasmTransferParams;
    withBitSize(bit_size: number): WasmTransferParams;
    /**
     * Amount to transfer
     */
    amount: string;
    /**
     * Optional auditor public key
     */
    get auditor_public_key(): string | undefined;
    /**
     * Optional auditor public key
     */
    set auditor_public_key(value: string | null | undefined);
    /**
     * Bit size for range proof (default: 40)
     */
    get bit_size(): number | undefined;
    /**
     * Bit size for range proof (default: 40)
     */
    set bit_size(value: number | null | undefined);
    /**
     * Chain ID (hex)
     */
    chain_id: string;
    /**
     * Current balance ciphertext
     */
    current_cipher_l_x: string;
    current_cipher_l_y: string;
    current_cipher_r_x: string;
    current_cipher_r_y: string;
    /**
     * Transaction nonce (hex)
     */
    nonce: string;
    /**
     * Recipient's Tongo public key
     */
    recipient_public_key: string;
    /**
     * Sender address (hex)
     */
    sender_address: string;
    /**
     * Tongo contract address (hex)
     */
    tongo_address: string;
}

/**
 * Result of a transfer proof generation.
 */
export class WasmTransferProofResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Audit for balance (if auditor configured)
     */
    get audit_balance_json(): string | undefined;
    /**
     * Audit for balance (if auditor configured)
     */
    set audit_balance_json(value: string | null | undefined);
    /**
     * Audit for transfer (if auditor configured)
     */
    get audit_transfer_json(): string | undefined;
    /**
     * Audit for transfer (if auditor configured)
     */
    set audit_transfer_json(value: string | null | undefined);
    /**
     * Auxiliar cipher 2 (R_aux2 = g^r2)
     */
    aux2_r_x: string;
    aux2_r_y: string;
    /**
     * Auxiliar cipher 2 (V2 = g^b_left*h^r2)
     */
    aux2_v_x: string;
    aux2_v_y: string;
    /**
     * Auxiliar cipher (R_aux = g^r)
     */
    aux_r_x: string;
    aux_r_y: string;
    /**
     * Auxiliar cipher (V = g^b*h^r)
     */
    aux_v_x: string;
    aux_v_y: string;
    /**
     * New balance cipher (L)
     */
    new_balance_l_x: string;
    new_balance_l_y: string;
    /**
     * New balance cipher (R)
     */
    new_balance_r_x: string;
    new_balance_r_y: string;
    /**
     * Complete transfer proof as JSON
     */
    proof_json: string;
    /**
     * Transfer cipher for self (L)
     */
    self_l_x: string;
    self_l_y: string;
    /**
     * Transfer cipher for self (R)
     */
    self_r_x: string;
    self_r_y: string;
    /**
     * Transfer cipher for recipient (L)
     */
    transfer_l_x: string;
    transfer_l_y: string;
    /**
     * Transfer cipher for recipient (R)
     */
    transfer_r_x: string;
    transfer_r_y: string;
}

/**
 * Transaction type enum for Tongo operations.
 */
export enum WasmTxType {
    Fund = 0,
    Transfer = 1,
    Rollover = 2,
    Withdraw = 3,
    Ragequit = 4,
}

/**
 * Parameters for generating a withdraw proof.
 */
export class WasmWithdrawParams {
    free(): void;
    [Symbol.dispose](): void;
    constructor(recipient_address: string, amount: string, nonce: string, chain_id: string, tongo_address: string, sender_address: string, current_cipher_l_x: string, current_cipher_l_y: string, current_cipher_r_x: string, current_cipher_r_y: string);
    withAuditor(auditor_public_key: string): WasmWithdrawParams;
    withBitSize(bit_size: number): WasmWithdrawParams;
    /**
     * Amount to withdraw
     */
    amount: string;
    /**
     * Optional auditor public key
     */
    get auditor_public_key(): string | undefined;
    /**
     * Optional auditor public key
     */
    set auditor_public_key(value: string | null | undefined);
    /**
     * Bit size for range proof (default: 40)
     */
    get bit_size(): number | undefined;
    /**
     * Bit size for range proof (default: 40)
     */
    set bit_size(value: number | null | undefined);
    /**
     * Chain ID (hex)
     */
    chain_id: string;
    /**
     * Current balance ciphertext
     */
    current_cipher_l_x: string;
    current_cipher_l_y: string;
    current_cipher_r_x: string;
    current_cipher_r_y: string;
    /**
     * Transaction nonce (hex)
     */
    nonce: string;
    /**
     * Recipient address for withdrawn funds (hex)
     */
    recipient_address: string;
    /**
     * Sender address (hex)
     */
    sender_address: string;
    /**
     * Tongo contract address (hex)
     */
    tongo_address: string;
}

/**
 * Result of a withdraw proof generation.
 */
export class WasmWithdrawProofResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    a_r_x: string;
    a_r_y: string;
    a_v_x: string;
    a_v_y: string;
    a_x2: string;
    /**
     * Commitments
     */
    a_x_x: string;
    a_x_y: string;
    a_y2: string;
    /**
     * Amount withdrawn
     */
    amount: string;
    /**
     * Audit data as JSON (if auditor configured)
     */
    get audit_json(): string | undefined;
    /**
     * Audit data as JSON (if auditor configured)
     */
    set audit_json(value: string | null | undefined);
    /**
     * Auxiliar cipher (R_aux = g^r)
     */
    aux_r_x: string;
    aux_r_y: string;
    /**
     * Auxiliar cipher (V = g^b_left*h^r)
     */
    aux_v_x: string;
    aux_v_y: string;
    /**
     * Range proof as JSON
     */
    range_json: string;
    /**
     * Recipient address
     */
    recipient: string;
    sb: string;
    sr: string;
    /**
     * Scalar responses
     */
    sx: string;
    /**
     * Public key Y point
     */
    y_x: string;
    y_y: string;
}

/**
 * Calculate a Starknet contract address from deployment parameters.
 *
 * Implements the standard contract address derivation formula using
 * `computeHashOnElements`.
 *
 * # Arguments
 * * `salt` - Salt value (hex string)
 * * `class_hash` - Contract class hash (hex string)
 * * `constructor_calldata` - Array of hex strings for constructor calldata
 * * `deployer_address` - Deployer address (hex string, typically "0x0")
 *
 * # Returns
 * The calculated contract address as hex string
 */
export function calculateContractAddress(salt: string, class_hash: string, constructor_calldata: string[], deployer_address: string): string;

/**
 * Compile an array of calls into the Starknet multicall `__execute__` ABI
 * format.
 *
 * The returned vector of hex strings encodes:
 * ```text
 * [
 *     call_array_len,
 *     // per call: to, selector, data_offset, data_len
 *     ...,
 *     total_calldata_len,
 *     // all calldata values concatenated
 *     ...
 * ]
 * ```
 *
 * # Arguments
 * * `calls_json` — a JSON array of `Call` objects:
 *   ```json
 *   [{ "contractAddress": "0x…", "entrypoint": "transfer", "calldata": ["0x1", "0x2"] }]
 *   ```
 *
 * # Errors
 * Returns `JsValue` (string) on invalid JSON, invalid hex, etc.
 */
export function compileCalls(calls_json: string): string[];

/**
 * Compute the hash of a declare transaction (v2).
 */
export function computeDeclareTransactionHashV2(sender_address: string, class_hash: string, max_fee: string, chain_id: string, nonce: string, compiled_class_hash: string): string;

/**
 * Compute the hash of a declare transaction (v3).
 */
export function computeDeclareTransactionHashV3(sender_address: string, class_hash: string, chain_id: string, nonce: string, compiled_class_hash: string, tip: string, resource_bounds: any, paymaster_data: string[], nonce_data_availability_mode: number, fee_data_availability_mode: number, account_deployment_data: string[]): string;

/**
 * Compute the hash of a deploy account transaction (v1).
 */
export function computeDeployAccountTransactionHashV1(contract_address: string, class_hash: string, constructor_calldata: string[], salt: string, max_fee: string, chain_id: string, nonce: string): string;

/**
 * Compute the hash of a deploy account transaction (v3).
 */
export function computeDeployAccountTransactionHashV3(contract_address: string, class_hash: string, constructor_calldata: string[], salt: string, chain_id: string, nonce: string, tip: string, resource_bounds: any, paymaster_data: string[], nonce_data_availability_mode: number, fee_data_availability_mode: number): string;

/**
 * Compute the hash of an invoke transaction (v1).
 *
 * All felt arguments are hex strings (e.g. `"0x1234"`).
 */
export function computeInvokeTransactionHashV1(sender_address: string, calldata: string[], max_fee: string, chain_id: string, nonce: string): string;

/**
 * Compute the hash of an invoke transaction (v3).
 */
export function computeInvokeTransactionHashV3(sender_address: string, calldata: string[], chain_id: string, nonce: string, tip: string, resource_bounds: any, paymaster_data: string[], nonce_data_availability_mode: number, fee_data_availability_mode: number, account_deployment_data: string[], proof_facts?: string[] | null): string;

/**
 * Compute the SNIP-12 typed data message hash.
 *
 * # Arguments
 * * `typed_data_json` - JSON string conforming to the SNIP-12 typed data schema.
 * * `account_address` - Hex-encoded Starknet account address.
 *
 * # Returns
 * The message hash as a hex string.
 */
export function computeTypedDataMessageHash(typed_data_json: string, account_address: string): string;

/**
 * Decode a Cairo short-string Felt back to a UTF-8 string.
 *
 * # Arguments
 * * `felt_hex` — `0x`-prefixed hex representation of the felt.
 *
 * # Returns
 * The decoded string.
 */
export function decodeShortString(felt_hex: string): string;

/**
 * Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
 *
 * @param keystoreJson - JSON keystore string in ethers.js format
 * @param password - The password used during encryption
 * @returns Decrypted content as hex string (typically a private key)
 */
export function decryptEthersKeystore(keystore_json: string, password: string): string;

/**
 * Decrypt a krusty-kms keystore (version 1) to recover the mnemonic.
 *
 * @param keystoreJson - JSON keystore string
 * @param password - The password used during encryption
 * @returns Decrypted mnemonic phrase
 */
export function decryptKeystore(keystore_json: string, password: string): string;

/**
 * Decrypt a private key that was encrypted with `encryptPrivateKey`.
 *
 * @param nonce - Hex-encoded 24-byte nonce
 * @param salt - Hex-encoded 16-byte salt
 * @param encryptedKey - Hex-encoded ciphertext
 * @param password - The password used during encryption
 * @param scryptN - The same scrypt cost parameter used during encryption
 * @returns Hex-encoded private key (no 0x prefix)
 */
export function decryptPrivateKey(nonce: string, salt: string, encrypted_key: string, password: string, scrypt_n: number): string;

/**
 * Decrypt data that was encrypted with `encryptWithKey`.
 *
 * @param nonce - Hex-encoded 24-byte nonce
 * @param ciphertext - Hex-encoded ciphertext
 * @param keyHex - Hex-encoded 32-byte key (64 hex chars)
 * @returns Decrypted plaintext as a UTF-8 string
 */
export function decryptWithKey(nonce: string, ciphertext: string, key_hex: string): string;

/**
 * Derive an Argent account contract address from a public key.
 *
 * Uses the standard Argent constructor calldata format `(0, public_key, 0)`.
 *
 * # Arguments
 * * `public_key` - The Stark public key (hex string)
 * * `class_hash` - Optional custom class hash (hex string). Defaults to the
 *   standard Argent v0.4.0 class hash.
 *
 * # Returns
 * The derived account contract address as hex string
 */
export function deriveArgentAccountAddress(public_key: string, class_hash?: string | null): string;

/**
 * Derive a Starknet keypair using old Argent's "double derivation" scheme.
 *
 * Old Argent wallets use a two-step derivation:
 * 1. Derive ETH private key at `m/44'/60'/0'/0/0` (raw, no grindKey)
 * 2. Use ETH key as BIP-32 seed, derive `m/44'/9004'/0'/0/{index}`, then grindKey
 *
 * This is needed to recover keys for accounts created with old Argent-X.
 * Braavos and new Argent use direct `m/44'/9004'/0'/0/{index}` derivation instead.
 *
 * # Arguments
 * * `mnemonic` - 12 or 24 word BIP-39 mnemonic
 * * `address_index` - HD wallet address index (default: 0)
 * * `account_index` - HD wallet account index (default: 0)
 */
export function deriveArgentLegacyKeypair(mnemonic: string, address_index: number, account_index: number): WasmKeypair;

/**
 * Derive a Braavos account contract address from a public key.
 *
 * Uses the standard Braavos constructor calldata format `(public_key)`.
 *
 * # Arguments
 * * `public_key` - The Stark public key (hex string)
 * * `class_hash` - Optional custom class hash (hex string). Defaults to the
 *   standard Braavos v1.0.0 class hash.
 *
 * # Returns
 * The derived account contract address as hex string
 */
export function deriveBraavosAccountAddress(public_key: string, class_hash?: string | null): string;

/**
 * Derive all unique keypairs for a mnemonic without computing addresses.
 *
 * Returns one keypair per derivation scheme per index:
 * - **Direct**: `m/44'/9004'/0'/0/{index}` — shared by Braavos, new Argent, OpenZeppelin
 * - **ArgentLegacy**: double derivation via ETH key — used by legacy Argent wallets
 *
 * This is cheaper than `generateAccountCandidates` since it skips address computation.
 * Use these public keys to query external APIs (e.g., Argent's smart account
 * discovery endpoint) for accounts whose addresses can't be derived locally.
 *
 * # Returns
 * JSON string: array of objects with fields:
 * - `derivationType`: "Direct" | "ArgentLegacy"
 * - `publicKey`: hex string
 * - `privateKey`: hex string (handle with care!)
 * - `derivationIndex`: number
 * - `derivationPath`: string
 *
 * # Example (JavaScript)
 * ```javascript
 * const keypairs = JSON.parse(deriveDiscoveryKeypairs(mnemonic, 5));
 *
 * // Use public keys to query Argent's smart account API
 * for (const kp of keypairs) {
 *   const smartAccounts = await argentApi.findAccountsByPublicKey(kp.publicKey);
 *   // smartAccounts contains addresses with server-provided salts
 * }
 * ```
 */
export function deriveDiscoveryKeypairs(mnemonic: string, max_index?: number | null): string;

/**
 * Derive a keypair from mnemonic (for external use).
 */
export function deriveKeypair(mnemonic: string, address_index: number, account_index: number, passphrase?: string | null): WasmKeypair;

/**
 * Derive a Nostr keypair from mnemonic (coin type 1237).
 *
 * Uses secp256k1 curve (not Stark curve). The public key is x-only
 * (32 bytes) as per BIP-340/Nostr convention.
 *
 * Derivation path: m/44'/1237'/{account_index}'/0/{address_index}
 *
 * # Arguments
 * * `mnemonic` - 12 or 24 word BIP-39 mnemonic
 * * `address_index` - HD wallet address index (default: 0)
 * * `account_index` - HD wallet account index (default: 0)
 * * `passphrase` - Optional BIP-39 passphrase
 *
 * # Returns
 * Nostr keypair with private key and x-only public key (both 64 hex chars)
 */
export function deriveNostrKeypair(mnemonic: string, address_index: number, account_index: number, passphrase?: string | null): WasmNostrKeypair;

/**
 * Derive an OpenZeppelin account contract address from a public key.
 *
 * This calculates the counterfactual address for an OpenZeppelin account
 * using the standard contract address derivation formula.
 *
 * # Arguments
 * * `public_key_x` - The x-coordinate of the Stark public key (hex string)
 * * `class_hash` - The OpenZeppelin account class hash (hex string)
 * * `salt` - Optional salt for address derivation (hex string, defaults to "0x0")
 *
 * # Returns
 * The derived account contract address as hex string
 */
export function deriveOzAccountAddress(public_key_x: string, class_hash: string, salt?: string | null): string;

/**
 * Derive a Starknet account keypair from mnemonic (coin type 9004).
 *
 * This is used for signing Starknet transactions and deriving the
 * OpenZeppelin account contract address.
 *
 * # Arguments
 * * `mnemonic` - 12 or 24 word BIP-39 mnemonic
 * * `address_index` - HD wallet address index (default: 0)
 * * `account_index` - HD wallet account index (default: 0)
 * * `passphrase` - Optional BIP-39 passphrase
 *
 * # Returns
 * Keypair with private key and public key coordinates
 */
export function deriveStarknetKeypair(mnemonic: string, address_index: number, account_index: number, passphrase?: string | null): WasmKeypair;

/**
 * Derive the STRK20 viewing key from a Stark private key.
 *
 * The viewing key is `Pedersen(starknet_keccak(DOMAIN), private_key) mod (n/2) + 1`,
 * matching the Starknet Privacy SDK's expected `[1, n/2]` range.
 *
 * # Arguments
 * * `private_key` - The Stark private key as a hex string.
 *
 * # Returns
 * The viewing key as a `0x`-prefixed hex string.
 */
export function deriveStrk20ViewingKey(private_key: string): string;

/**
 * Deserialize a public key from hex format to (x, y) coordinates.
 *
 * # Arguments
 * * `hex` - Public key in "0x{x}{y}" format (128 hex chars after 0x)
 *
 * # Returns
 * Object with x and y properties
 */
export function deserializePublicKey(hex: string): WasmPoint;

/**
 * Perform full account discovery in a single call.
 *
 * Returns a JSON object with two fields:
 * - `keypairs`: array of DerivedKeypair objects (for API-based smart account lookup)
 * - `candidates`: array of CandidateAccount objects (for local address derivation)
 *
 * This combines `deriveDiscoveryKeypairs` and `generateAccountCandidates` into
 * a single WASM call, eliminating one JS→WASM round-trip.
 */
export function discoverAccountsFromMnemonic(mnemonic: string, max_index?: number | null): string;

/**
 * Encode a value as a Felt hex string.
 *
 * Supported input formats:
 * - Hex string (`"0x1a"`)
 * - Decimal number string (`"42"`)
 * - Boolean (`"true"` / `"false"`)
 *
 * # Returns
 * The Felt as a `0x`-prefixed hex string.
 */
export function encodeFelt(value: string): string;

/**
 * Encode a short ASCII string (<=31 chars) as a Cairo short-string Felt.
 *
 * # Returns
 * The Felt as a `0x`-prefixed hex string.
 */
export function encodeShortString(s: string): string;

/**
 * Encrypt a mnemonic into a JSON keystore string (krusty-kms format, version 1).
 *
 * @param mnemonic - Mnemonic phrase to encrypt
 * @param password - Encryption password
 * @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
 * @returns JSON keystore string
 */
export function encryptKeystore(mnemonic: string, password: string, scrypt_n: number): string;

/**
 * Encrypt a hex-encoded private key with a password (scrypt + XChaCha20-Poly1305).
 *
 * @param privateKeyHex - Private key in hex (with or without 0x prefix)
 * @param password - Encryption password
 * @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
 * @returns Encrypted key with hex-encoded nonce, salt, and ciphertext
 */
export function encryptPrivateKey(private_key_hex: string, password: string, scrypt_n: number): WasmEncryptedKey;

/**
 * Encrypt a plaintext string with a pre-derived 32-byte key.
 *
 * @param plaintext - UTF-8 string to encrypt
 * @param keyHex - Hex-encoded 32-byte key (64 hex chars)
 * @returns Encrypted payload with hex-encoded nonce and ciphertext
 */
export function encryptWithKey(plaintext: string, key_hex: string): WasmEncryptedPayload;

/**
 * Generate a compact summary of candidate addresses grouped by derivation index.
 *
 * Returns a JSON object where keys are derivation indices and values are
 * objects mapping wallet type to address. Useful for quick discovery without
 * needing the full candidate details.
 *
 * # Returns
 * JSON string: `{ "0": { "Braavos": "0x...", "Argent": "0x...", ... }, "1": { ... } }`
 */
export function generateAccountAddresses(mnemonic: string, max_index?: number | null): string;

/**
 * Generate all candidate account addresses for a mnemonic.
 *
 * Returns a JSON array of candidate accounts across all known wallet types
 * (Braavos, Argent, Argent Legacy, Argent Cairo 0, OpenZeppelin).
 *
 * This is a pure cryptographic operation — no network calls are made.
 * Each candidate is a possible on-chain account address. To find which
 * ones are actually deployed, check each address via an RPC provider
 * (e.g., `provider.getClassHashAt(address)` in starknet.js).
 *
 * # Arguments
 * * `mnemonic` - BIP-39 mnemonic phrase (12 or 24 words)
 * * `max_index` - Maximum derivation index to scan (default: 5).
 *   Higher values scan more potential accounts but take longer.
 *
 * # Returns
 * JSON string: array of objects with fields:
 * - `walletType`: "Braavos" | "Argent" | "ArgentLegacy" | "ArgentCairo0" | "OpenZeppelin"
 * - `classHash`: hex string
 * - `address`: hex string
 * - `publicKey`: hex string
 * - `privateKey`: hex string (handle with care!)
 * - `derivationIndex`: number
 * - `derivationPath`: string (e.g., "m/44'/9004'/0'/0/0")
 * - `classVersion`: string (e.g., "v0.4.0", "braavos-base")
 *
 * # Example (JavaScript)
 * ```javascript
 * const candidates = JSON.parse(generateAccountCandidates(mnemonic, 3));
 * for (const c of candidates) {
 *   const deployed = await provider.getClassHashAt(c.address).catch(() => null);
 *   if (deployed) {
 *     console.log(`Found ${c.walletType} account at ${c.address}`);
 *   }
 * }
 * ```
 */
export function generateAccountCandidates(mnemonic: string, max_index?: number | null): string;

/**
 * Generate a fund (deposit) proof.
 */
export function generateFundProof(account: WasmAccount, params: WasmFundParams): WasmFundProofResult;

/**
 * Generate a new random mnemonic phrase.
 */
export function generateMnemonic(word_count?: number | null): string;

/**
 * Generate a ragequit (emergency exit) proof.
 */
export function generateRagequitProof(account: WasmAccount, params: WasmRagequitParams): WasmRagequitProofResult;

/**
 * Generate a rollover proof.
 */
export function generateRolloverProof(account: WasmAccount, params: WasmRolloverParams): WasmRolloverProofResult;

/**
 * Generate a transfer proof.
 */
export function generateTransferProof(account: WasmAccount, params: WasmTransferParams): WasmTransferProofResult;

/**
 * Generate a withdraw proof.
 */
export function generateWithdrawProof(account: WasmAccount, params: WasmWithdrawParams): WasmWithdrawProofResult;

/**
 * Get known account class hashes for common Starknet account implementations.
 *
 * Returns a JSON string containing class hashes organized by account type
 * and version, covering OpenZeppelin, Argent, and Braavos accounts.
 *
 * # Returns
 * JSON string with nested object: `{ oz: { ... }, argent: { ... }, braavos: { ... } }`
 */
export function getAccountClassHashes(): string;

/**
 * Get build information.
 */
export function getBuildInfo(): any;

/**
 * Get the Stark curve generator point.
 */
export function getGenerator(): WasmPoint;

/**
 * Get the Nostr coin type constant (1237).
 */
export function getNostrCoinType(): number;

/**
 * Get a Starknet function selector from a function name.
 *
 * Equivalent to `starknet_keccak(name.as_bytes())`.
 *
 * # Arguments
 * * `name` - The function name (e.g. `"transfer"`)
 *
 * # Returns
 * The selector as a hex string
 */
export function getSelectorFromName(name: string): string;

/**
 * Get the Starknet coin type constant (9004).
 */
export function getStarknetCoinType(): number;

/**
 * Get the Tongo coin type constant (5454).
 */
export function getTongoCoinType(): number;

/**
 * Get the SDK version.
 */
export function getVersion(): string;

/**
 * Grind a 32-byte seed into a valid Stark private key.
 *
 * Implements the standard Stark key grinding algorithm that ensures
 * the output is a valid scalar on the Stark curve (less than the curve order).
 *
 * # Arguments
 * * `seed_hex` - Hex-encoded 32-byte seed (with or without `0x` prefix)
 *
 * # Returns
 * The ground key as a hex string
 */
export function grindKey(seed_hex: string): string;

/**
 * Initialize the WASM module.
 *
 * Sets up panic hook for better error messages in console.
 * Call this before using any other functions.
 */
export function init(): void;

/**
 * Check whether a hex string is a valid Stark field element.
 *
 * # Arguments
 * * `hex_str` - Hex string to validate (with or without `0x` prefix)
 *
 * # Returns
 * `true` if the string parses as a valid felt, `false` otherwise
 */
export function isValidFelt(hex_str: string): boolean;

/**
 * Check whether a hex string is a valid Stark private key.
 *
 * A valid private key must parse as a felt and must not be zero.
 *
 * # Arguments
 * * `hex_str` - Hex string to validate (with or without `0x` prefix)
 *
 * # Returns
 * `true` if the string is a non-zero valid felt, `false` otherwise
 */
export function isValidStarkPrivateKey(hex_str: string): boolean;

/**
 * Derive the x-only Nostr public key for a secp256k1 private key.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 *
 * # Returns
 * x-only public key as 64 hex chars (no 0x prefix)
 */
export function nostrPublicKey(private_key: string): string;

/**
 * Compute the Pedersen hash of two field elements.
 *
 * # Arguments
 * * `a` - First element as a hex string
 * * `b` - Second element as a hex string
 *
 * # Returns
 * The Pedersen hash as a hex string
 */
export function pedersenHash(a: string, b: string): string;

/**
 * Compute `computeHashOnElements` over an array of field elements.
 *
 * This chains Pedersen hashes starting from zero:
 * `pedersen(pedersen(pedersen(0, e0), e1), ..., len)`
 *
 * # Arguments
 * * `felts` - Array of hex strings (felt values)
 *
 * # Returns
 * The hash as a hex string
 */
export function pedersenHashMany(felts: string[]): string;

/**
 * Add two points on the Stark curve.
 */
export function pointAdd(p1_x: string, p1_y: string, p2_x: string, p2_y: string): WasmPoint;

/**
 * Compute Poseidon hash of exactly two field elements.
 *
 * # Arguments
 * * `a` - First input (hex string)
 * * `b` - Second input (hex string)
 *
 * # Returns
 * The Poseidon hash as a hex string
 */
export function poseidonHash(a: string, b: string): string;

/**
 * Compute a Poseidon hash of the given inputs.
 *
 * # Arguments
 * * `inputs` - Array of hex strings (felt values)
 *
 * # Returns
 * The hash as a hex string
 */
export function poseidonHashMany(inputs: string[]): string;

/**
 * Generate random bytes and return them as a hex string.
 *
 * Uses a cryptographically secure random number generator.
 *
 * # Arguments
 * * `length` - Number of random bytes to generate
 *
 * # Returns
 * Hex-encoded bytes with `0x` prefix
 */
export function randomBytesHex(length: number): string;

/**
 * Generate a random field element.
 */
export function randomFelt(): string;

/**
 * Multiply a point by a scalar.
 *
 * # Arguments
 * * `scalar` - Scalar value (hex string)
 * * `point_x` - Point X coordinate (hex string)
 * * `point_y` - Point Y coordinate (hex string)
 *
 * # Returns
 * Resulting point as {x, y} object
 */
export function scalarMul(scalar: string, point_x: string, point_y: string): WasmPoint;

/**
 * Multiply the generator point by a scalar.
 *
 * # Arguments
 * * `scalar` - Scalar value (hex string)
 *
 * # Returns
 * Resulting point as {x, y} object
 */
export function scalarMulGenerator(scalar: string): WasmPoint;

/**
 * Serialize a public key point to the standard hex format.
 *
 * # Arguments
 * * `x` - X coordinate (hex string)
 * * `y` - Y coordinate (hex string)
 *
 * # Returns
 * Concatenated "0x{x}{y}" format used by Tongo protocol
 */
export function serializePublicKey(x: string, y: string): string;

/**
 * Sign a 32-byte Nostr event id using BIP-340 Schnorr.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 * * `event_id` - 64 hex chars (no 0x prefix), the event id to sign
 *
 * # Returns
 * Signature result with public key and signature (both hex, no 0x prefix)
 */
export function signNostrEventId(private_key: string, event_id: string): WasmNostrSignature;

/**
 * Sign an arbitrary message using BIP-340 Schnorr.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 * * `message` - hex-encoded bytes (may have optional 0x prefix)
 *
 * # Returns
 * Signature result with public key and signature (both hex, no 0x prefix)
 */
export function signNostrMessage(private_key: string, message: string): WasmNostrSignature;

/**
 * Sign a message hash using Stark ECDSA.
 *
 * Uses deterministic RFC-6979 nonce generation.
 *
 * # Arguments
 * * `private_key` - Stark private key as hex string (0x-prefixed)
 * * `msg_hash` - Message hash as hex string (0x-prefixed)
 *
 * # Returns
 * Signature with r, s components and public key (all 0x-prefixed hex)
 */
export function signStarkHash(private_key: string, msg_hash: string): WasmStarkSignature;

/**
 * Derive the Stark public key corresponding to a private key.
 *
 * # Arguments
 * * `private_key` - Stark private key as hex string (0x-prefixed)
 *
 * # Returns
 * The public key as a hex string (0x-prefixed)
 */
export function starkPublicKey(private_key: string): string;

/**
 * Compute Starknet keccak: Keccak-256 truncated to 250 bits.
 *
 * # Arguments
 * * `data` - Input data (interpreted according to `encoding`)
 * * `encoding` - `"hex"` to hex-decode `data`, or `"utf8"` / `None` to use raw bytes
 *
 * # Returns
 * The Starknet keccak hash as a hex string
 */
export function starknetKeccak(data: string, encoding?: string | null): string;

/**
 * Validate a mnemonic phrase.
 */
export function validateMnemonic(mnemonic: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_get_wasmfundparams_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_auditor_public_key: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_chain_id: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_current_cipher_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_current_cipher_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_current_cipher_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_current_cipher_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_sender_address: (a: number) => [number, number];
    readonly __wbg_get_wasmfundparams_tongo_address: (a: number) => [number, number];
    readonly __wbg_get_wasmfundproofresult_audit_json: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_auditor_public_key: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_bit_size: (a: number) => number;
    readonly __wbg_get_wasmtransferparams_current_cipher_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_audit_balance_json: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_audit_transfer_json: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux2_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux2_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux2_v_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux2_v_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_new_balance_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_new_balance_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_new_balance_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_new_balance_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_proof_json: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_audit_json: (a: number) => [number, number];
    readonly __wbg_set_wasmfundparams_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_auditor_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_chain_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_current_cipher_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_current_cipher_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_current_cipher_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_current_cipher_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_sender_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundparams_tongo_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundproofresult_audit_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_auditor_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_bit_size: (a: number, b: number) => void;
    readonly __wbg_set_wasmtransferparams_current_cipher_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_audit_balance_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_audit_transfer_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux2_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux2_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux2_v_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux2_v_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_new_balance_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_new_balance_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_new_balance_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_new_balance_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_proof_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_audit_json: (a: number, b: number, c: number) => void;
    readonly __wbg_wasmfundparams_free: (a: number, b: number) => void;
    readonly __wbg_wasmfundproofresult_free: (a: number, b: number) => void;
    readonly __wbg_wasmragequitparams_free: (a: number, b: number) => void;
    readonly __wbg_wasmragequitproofresult_free: (a: number, b: number) => void;
    readonly __wbg_wasmrolloverparams_free: (a: number, b: number) => void;
    readonly __wbg_wasmrolloverproofresult_free: (a: number, b: number) => void;
    readonly __wbg_wasmtransferparams_free: (a: number, b: number) => void;
    readonly __wbg_wasmtransferproofresult_free: (a: number, b: number) => void;
    readonly __wbg_wasmwithdrawparams_free: (a: number, b: number) => void;
    readonly __wbg_wasmwithdrawproofresult_free: (a: number, b: number) => void;
    readonly generateFundProof: (a: number, b: number) => [number, number, number];
    readonly generateRagequitProof: (a: number, b: number) => [number, number, number];
    readonly generateRolloverProof: (a: number, b: number) => [number, number, number];
    readonly generateTransferProof: (a: number, b: number) => [number, number, number];
    readonly generateWithdrawProof: (a: number, b: number) => [number, number, number];
    readonly wasmfundparams_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => number;
    readonly wasmfundparams_withAuditor: (a: number, b: number, c: number) => number;
    readonly wasmrolloverparams_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly wasmtransferparams_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number) => number;
    readonly wasmtransferparams_withAuditor: (a: number, b: number, c: number) => number;
    readonly wasmtransferparams_withBitSize: (a: number, b: number) => number;
    readonly wasmwithdrawparams_withBitSize: (a: number, b: number) => number;
    readonly wasmwithdrawparams_withAuditor: (a: number, b: number, c: number) => number;
    readonly __wbg_get_wasmfundproofresult_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmfundproofresult_proof_json: (a: number) => [number, number];
    readonly __wbg_get_wasmfundproofresult_y_x: (a: number) => [number, number];
    readonly __wbg_get_wasmfundproofresult_y_y: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_chain_id: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_current_cipher_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_current_cipher_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_current_cipher_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_current_cipher_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_recipient_address: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_sender_address: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitparams_tongo_address: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_a_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_a_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_a_x_x: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_a_x_y: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_recipient: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_sx: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_y_x: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_y_y: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverparams_chain_id: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverparams_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverparams_sender_address: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverparams_tongo_address: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverproofresult_pending_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverproofresult_proof_json: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverproofresult_y_x: (a: number) => [number, number];
    readonly __wbg_get_wasmrolloverproofresult_y_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_chain_id: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_current_cipher_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_current_cipher_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_current_cipher_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_recipient_public_key: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_sender_address: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferparams_tongo_address: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux_v_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_aux_v_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_self_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_self_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_self_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_self_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_transfer_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_transfer_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_transfer_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmtransferproofresult_transfer_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_chain_id: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_current_cipher_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_current_cipher_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_current_cipher_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_current_cipher_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_recipient_address: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_sender_address: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_tongo_address: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_v_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_v_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_x2: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_x_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_x_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_a_y2: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_amount: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_aux_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_aux_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_aux_v_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_aux_v_y: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_range_json: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_recipient: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_sb: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_sr: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_sx: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_y_x: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawproofresult_y_y: (a: number) => [number, number];
    readonly __wbg_set_wasmragequitparams_auditor_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_audit_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_auditor_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_get_wasmragequitparams_auditor_public_key: (a: number) => [number, number];
    readonly __wbg_get_wasmragequitproofresult_audit_json: (a: number) => [number, number];
    readonly __wbg_get_wasmwithdrawparams_auditor_public_key: (a: number) => [number, number];
    readonly wasmwithdrawparams_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number) => number;
    readonly __wbg_set_wasmfundproofresult_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundproofresult_proof_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundproofresult_y_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmfundproofresult_y_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_chain_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_current_cipher_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_current_cipher_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_current_cipher_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_current_cipher_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_recipient_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_sender_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitparams_tongo_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_a_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_a_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_a_x_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_a_x_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_recipient: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_sx: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_y_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmragequitproofresult_y_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverparams_chain_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverparams_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverparams_sender_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverparams_tongo_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverproofresult_pending_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverproofresult_proof_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverproofresult_y_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmrolloverproofresult_y_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_chain_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_current_cipher_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_current_cipher_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_current_cipher_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_recipient_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_sender_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferparams_tongo_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux_v_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_aux_v_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_self_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_self_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_self_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_self_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_transfer_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_transfer_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_transfer_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmtransferproofresult_transfer_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_chain_id: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_current_cipher_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_current_cipher_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_current_cipher_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_current_cipher_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_recipient_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_sender_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawparams_tongo_address: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_v_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_v_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_x2: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_x_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_x_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_a_y2: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_amount: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_aux_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_aux_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_aux_v_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_aux_v_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_range_json: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_recipient: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_sb: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_sr: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_sx: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_y_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmwithdrawproofresult_y_y: (a: number, b: number, c: number) => void;
    readonly wasmragequitparams_withAuditor: (a: number, b: number, c: number) => number;
    readonly wasmragequitparams_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number) => number;
    readonly __wbg_get_wasmwithdrawparams_bit_size: (a: number) => number;
    readonly __wbg_set_wasmwithdrawparams_bit_size: (a: number, b: number) => void;
    readonly __wbg_wasmaccount_free: (a: number, b: number) => void;
    readonly calculateContractAddress: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly deriveArgentAccountAddress: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deriveArgentLegacyKeypair: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly deriveBraavosAccountAddress: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deriveKeypair: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly deriveNostrKeypair: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly deriveOzAccountAddress: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly deriveStarknetKeypair: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly generateMnemonic: (a: number) => [number, number, number, number];
    readonly getAccountClassHashes: () => [number, number];
    readonly getNostrCoinType: () => number;
    readonly getStarknetCoinType: () => number;
    readonly getTongoCoinType: () => number;
    readonly validateMnemonic: (a: number, b: number) => number;
    readonly wasmaccount_contractAddress: (a: number) => [number, number];
    readonly wasmaccount_decryptBalance: (a: number, b: number, c: number, d: bigint) => [number, number, number, number];
    readonly wasmaccount_decryptToPoint: (a: number, b: number) => [number, number, number];
    readonly wasmaccount_fromMnemonic: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly wasmaccount_fromPrivateKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasmaccount_getState: (a: number) => number;
    readonly wasmaccount_hasSufficientBalance: (a: number, b: number, c: number) => [number, number, number];
    readonly wasmaccount_ownerPublicKeyHex: (a: number) => [number, number, number, number];
    readonly wasmaccount_totalBalance: (a: number) => [number, number, number, number];
    readonly wasmaccount_updateState: (a: number, b: number) => [number, number];
    readonly __wbg_get_wasmaccountstate_balance: (a: number) => [number, number];
    readonly __wbg_get_wasmaccountstate_nonce: (a: number) => bigint;
    readonly __wbg_get_wasmaccountstate_pending_balance: (a: number) => [number, number];
    readonly __wbg_get_wasmciphertext_l_x: (a: number) => [number, number];
    readonly __wbg_get_wasmciphertext_r_y: (a: number) => [number, number];
    readonly __wbg_get_wasmdecryptedpoint_is_identity: (a: number) => number;
    readonly __wbg_get_wasmdecryptedpoint_x: (a: number) => [number, number];
    readonly __wbg_get_wasmdecryptedpoint_y: (a: number) => [number, number];
    readonly __wbg_set_wasmaccountstate_balance: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmaccountstate_nonce: (a: number, b: bigint) => void;
    readonly __wbg_set_wasmaccountstate_pending_balance: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmciphertext_l_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmciphertext_l_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmciphertext_r_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmdecryptedpoint_is_identity: (a: number, b: number) => void;
    readonly __wbg_set_wasmdecryptedpoint_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmdecryptedpoint_y: (a: number, b: number, c: number) => void;
    readonly __wbg_wasmaccountstate_free: (a: number, b: number) => void;
    readonly __wbg_wasmciphertext_free: (a: number, b: number) => void;
    readonly __wbg_wasmdecryptedpoint_free: (a: number, b: number) => void;
    readonly __wbg_wasmkeypair_free: (a: number, b: number) => void;
    readonly __wbg_wasmnostrkeypair_free: (a: number, b: number) => void;
    readonly __wbg_wasmnostrsignature_free: (a: number, b: number) => void;
    readonly __wbg_wasmpoint_free: (a: number, b: number) => void;
    readonly __wbg_wasmstarksignature_free: (a: number, b: number) => void;
    readonly wasmaccountstate_new: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number];
    readonly wasmaccountstate_totalBalance: (a: number) => [number, number, number, number];
    readonly wasmciphertext_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => number;
    readonly wasmdecryptedpoint_new: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly wasmkeypair_new: (a: number, b: number, c: number, d: number, e: number, f: number) => number;
    readonly wasmkeypair_publicKeyHex: (a: number) => [number, number];
    readonly wasmnostrkeypair_new: (a: number, b: number, c: number, d: number) => number;
    readonly wasmpoint_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly __wbg_get_wasmciphertext_l_y: (a: number) => [number, number];
    readonly __wbg_get_wasmciphertext_r_x: (a: number) => [number, number];
    readonly __wbg_get_wasmkeypair_private_key: (a: number) => [number, number];
    readonly __wbg_get_wasmkeypair_public_key_x: (a: number) => [number, number];
    readonly __wbg_get_wasmkeypair_public_key_y: (a: number) => [number, number];
    readonly __wbg_get_wasmnostrkeypair_private_key: (a: number) => [number, number];
    readonly __wbg_get_wasmnostrkeypair_public_key: (a: number) => [number, number];
    readonly __wbg_get_wasmnostrsignature_publicKey: (a: number) => [number, number];
    readonly __wbg_get_wasmnostrsignature_signature: (a: number) => [number, number];
    readonly __wbg_get_wasmpoint_x: (a: number) => [number, number];
    readonly __wbg_get_wasmpoint_y: (a: number) => [number, number];
    readonly __wbg_get_wasmstarksignature_publicKey: (a: number) => [number, number];
    readonly __wbg_get_wasmstarksignature_r: (a: number) => [number, number];
    readonly __wbg_get_wasmstarksignature_s: (a: number) => [number, number];
    readonly __wbg_set_wasmciphertext_r_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmkeypair_private_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmkeypair_public_key_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmkeypair_public_key_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmnostrkeypair_private_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmnostrkeypair_public_key: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmnostrsignature_publicKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmnostrsignature_signature: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmpoint_x: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmpoint_y: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmstarksignature_publicKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmstarksignature_r: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmstarksignature_s: (a: number, b: number, c: number) => void;
    readonly nostrPublicKey: (a: number, b: number) => [number, number, number, number];
    readonly signNostrEventId: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly signNostrMessage: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly signStarkHash: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly starkPublicKey: (a: number, b: number) => [number, number, number, number];
    readonly deriveStrk20ViewingKey: (a: number, b: number) => [number, number, number, number];
    readonly compileCalls: (a: number, b: number) => [number, number, number, number];
    readonly decodeShortString: (a: number, b: number) => [number, number, number, number];
    readonly encodeFelt: (a: number, b: number) => [number, number, number, number];
    readonly encodeShortString: (a: number, b: number) => [number, number, number, number];
    readonly getSelectorFromName: (a: number, b: number) => [number, number, number, number];
    readonly pedersenHash: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly pedersenHashMany: (a: number, b: number) => [number, number, number, number];
    readonly starknetKeccak: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deserializePublicKey: (a: number, b: number) => [number, number, number];
    readonly getBuildInfo: () => any;
    readonly getGenerator: () => number;
    readonly getVersion: () => [number, number];
    readonly pointAdd: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly poseidonHash: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly poseidonHashMany: (a: number, b: number) => [number, number, number, number];
    readonly randomFelt: () => [number, number];
    readonly scalarMul: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly scalarMulGenerator: (a: number, b: number) => [number, number, number];
    readonly serializePublicKey: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly init: () => void;
    readonly __wbg_get_wasmencryptedkey_encryptedKey: (a: number) => [number, number];
    readonly __wbg_get_wasmencryptedkey_nonce: (a: number) => [number, number];
    readonly __wbg_get_wasmencryptedkey_salt: (a: number) => [number, number];
    readonly __wbg_set_wasmencryptedkey_encryptedKey: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmencryptedkey_nonce: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmencryptedkey_salt: (a: number, b: number, c: number) => void;
    readonly __wbg_wasmencryptedkey_free: (a: number, b: number) => void;
    readonly __wbg_wasmencryptedpayload_free: (a: number, b: number) => void;
    readonly decryptEthersKeystore: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decryptKeystore: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decryptPrivateKey: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number, number];
    readonly decryptWithKey: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly encryptKeystore: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly encryptPrivateKey: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly encryptWithKey: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly grindKey: (a: number, b: number) => [number, number, number, number];
    readonly isValidFelt: (a: number, b: number) => number;
    readonly isValidStarkPrivateKey: (a: number, b: number) => number;
    readonly randomBytesHex: (a: number) => [number, number, number, number];
    readonly __wbg_get_wasmencryptedpayload_ciphertext: (a: number) => [number, number];
    readonly __wbg_get_wasmencryptedpayload_nonce: (a: number) => [number, number];
    readonly __wbg_set_wasmencryptedpayload_ciphertext: (a: number, b: number, c: number) => void;
    readonly __wbg_set_wasmencryptedpayload_nonce: (a: number, b: number, c: number) => void;
    readonly computeDeclareTransactionHashV2: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly computeDeclareTransactionHashV3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: any, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly computeDeployAccountTransactionHashV1: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly computeDeployAccountTransactionHashV3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: any, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly computeInvokeTransactionHashV1: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly computeInvokeTransactionHashV3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: any, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number) => [number, number, number, number];
    readonly computeTypedDataMessageHash: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly deriveDiscoveryKeypairs: (a: number, b: number, c: number) => [number, number, number, number];
    readonly discoverAccountsFromMnemonic: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generateAccountAddresses: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generateAccountCandidates: (a: number, b: number, c: number) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __externref_drop_slice: (a: number, b: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
