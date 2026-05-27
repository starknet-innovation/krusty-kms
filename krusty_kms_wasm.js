/* @ts-self-types="./krusty_kms_wasm.d.ts" */

/**
 * WASM-accessible Tongo account.
 *
 * Wraps the internal SDK account with JavaScript-friendly methods.
 * Handles key management and state tracking for confidential transactions.
 */
export class WasmAccount {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmAccount.prototype);
        obj.__wbg_ptr = ptr;
        WasmAccountFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmAccountFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmaccount_free(ptr, 0);
    }
    /**
     * Get the contract address as hex string.
     * @returns {string}
     */
    contractAddress() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmaccount_contractAddress(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
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
     * @param {WasmCiphertext} ciphertext
     * @param {bigint | null} [max_search]
     * @returns {string}
     */
    decryptBalance(ciphertext, max_search) {
        let deferred2_0;
        let deferred2_1;
        try {
            _assertClass(ciphertext, WasmCiphertext);
            const ret = wasm.wasmaccount_decryptBalance(this.__wbg_ptr, ciphertext.__wbg_ptr, !isLikeNone(max_search), isLikeNone(max_search) ? BigInt(0) : max_search);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
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
     * @param {WasmCiphertext} ciphertext
     * @returns {WasmDecryptedPoint}
     */
    decryptToPoint(ciphertext) {
        _assertClass(ciphertext, WasmCiphertext);
        const ret = wasm.wasmaccount_decryptToPoint(this.__wbg_ptr, ciphertext.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmDecryptedPoint.__wrap(ret[0]);
    }
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
     * @param {string} mnemonic
     * @param {number} address_index
     * @param {number} account_index
     * @param {string} contract_address
     * @param {string | null} [passphrase]
     * @returns {WasmAccount}
     */
    static fromMnemonic(mnemonic, address_index, account_index, contract_address, passphrase) {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(contract_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(passphrase) ? 0 : passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmaccount_fromMnemonic(ptr0, len0, address_index, account_index, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmAccount.__wrap(ret[0]);
    }
    /**
     * Create a new account from a private key.
     * # Arguments
     * * `private_key` - Private key as hex string (0x-prefixed)
     * * `contract_address` - Tongo contract address (hex string)
     * @param {string} private_key
     * @param {string} contract_address
     * @returns {WasmAccount}
     */
    static fromPrivateKey(private_key, contract_address) {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(contract_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmaccount_fromPrivateKey(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmAccount.__wrap(ret[0]);
    }
    /**
     * Get current account state.
     * @returns {WasmAccountState}
     */
    getState() {
        const ret = wasm.wasmaccount_getState(this.__wbg_ptr);
        return WasmAccountState.__wrap(ret);
    }
    /**
     * Check if account has sufficient balance for an operation.
     * @param {string} amount
     * @returns {boolean}
     */
    hasSufficientBalance(amount) {
        const ptr0 = passStringToWasm0(amount, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmaccount_hasSufficientBalance(this.__wbg_ptr, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Get the owner (spending) public key as hex string.
     * @returns {string}
     */
    ownerPublicKeyHex() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmaccount_ownerPublicKeyHex(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Get total balance (available + pending).
     * @returns {string}
     */
    totalBalance() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmaccount_totalBalance(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Update account state from on-chain data.
     * @param {WasmAccountState} state
     */
    updateState(state) {
        _assertClass(state, WasmAccountState);
        var ptr0 = state.__destroy_into_raw();
        const ret = wasm.wasmaccount_updateState(this.__wbg_ptr, ptr0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
}
if (Symbol.dispose) WasmAccount.prototype[Symbol.dispose] = WasmAccount.prototype.free;

/**
 * Account state returned from on-chain queries.
 */
export class WasmAccountState {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmAccountState.prototype);
        obj.__wbg_ptr = ptr;
        WasmAccountStateFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmAccountStateFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmaccountstate_free(ptr, 0);
    }
    /**
     * Available balance (can be spent immediately)
     * @returns {string}
     */
    get balance() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmaccountstate_balance(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Current nonce for replay protection
     * @returns {bigint}
     */
    get nonce() {
        const ret = wasm.__wbg_get_wasmaccountstate_nonce(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
    /**
     * Pending balance (requires rollover to become available)
     * @returns {string}
     */
    get pending_balance() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmaccountstate_pending_balance(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Available balance (can be spent immediately)
     * @param {string} arg0
     */
    set balance(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmaccountstate_balance(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Current nonce for replay protection
     * @param {bigint} arg0
     */
    set nonce(arg0) {
        wasm.__wbg_set_wasmaccountstate_nonce(this.__wbg_ptr, arg0);
    }
    /**
     * Pending balance (requires rollover to become available)
     * @param {string} arg0
     */
    set pending_balance(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmaccountstate_pending_balance(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Create a new account state.
     * @param {string} balance
     * @param {string} pending_balance
     * @param {bigint} nonce
     */
    constructor(balance, pending_balance, nonce) {
        const ptr0 = passStringToWasm0(balance, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pending_balance, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmaccountstate_new(ptr0, len0, ptr1, len1, nonce);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmAccountStateFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get total balance (available + pending).
     * @returns {string}
     */
    totalBalance() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.wasmaccountstate_totalBalance(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
}
if (Symbol.dispose) WasmAccountState.prototype[Symbol.dispose] = WasmAccountState.prototype.free;

/**
 * ElGamal ciphertext (L, R points).
 */
export class WasmCiphertext {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmCiphertextFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmciphertext_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmciphertext_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmciphertext_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmciphertext_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmciphertext_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {string} arg0
     */
    set l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmaccountstate_pending_balance(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} l_x
     * @param {string} l_y
     * @param {string} r_x
     * @param {string} r_y
     */
    constructor(l_x, l_y, r_x, r_y) {
        const ptr0 = passStringToWasm0(l_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(l_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(r_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(r_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmciphertext_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        this.__wbg_ptr = ret >>> 0;
        WasmCiphertextFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmCiphertext.prototype[Symbol.dispose] = WasmCiphertext.prototype.free;

/**
 * Decrypted point result that can explicitly represent the identity point.
 */
export class WasmDecryptedPoint {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmDecryptedPoint.prototype);
        obj.__wbg_ptr = ptr;
        WasmDecryptedPointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmDecryptedPointFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmdecryptedpoint_free(ptr, 0);
    }
    /**
     * @returns {boolean}
     */
    get is_identity() {
        const ret = wasm.__wbg_get_wasmdecryptedpoint_is_identity(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {string | undefined}
     */
    get x() {
        const ret = wasm.__wbg_get_wasmdecryptedpoint_x(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @returns {string | undefined}
     */
    get y() {
        const ret = wasm.__wbg_get_wasmdecryptedpoint_y(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {boolean} arg0
     */
    set is_identity(arg0) {
        wasm.__wbg_set_wasmdecryptedpoint_is_identity(this.__wbg_ptr, arg0);
    }
    /**
     * @param {string | null} [arg0]
     */
    set x(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmdecryptedpoint_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string | null} [arg0]
     */
    set y(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmdecryptedpoint_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {boolean} is_identity
     * @param {string | null} [x]
     * @param {string | null} [y]
     */
    constructor(is_identity, x, y) {
        var ptr0 = isLikeNone(x) ? 0 : passStringToWasm0(x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(y) ? 0 : passStringToWasm0(y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdecryptedpoint_new(is_identity, ptr0, len0, ptr1, len1);
        this.__wbg_ptr = ret >>> 0;
        WasmDecryptedPointFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmDecryptedPoint.prototype[Symbol.dispose] = WasmDecryptedPoint.prototype.free;

/**
 * Encrypted private key returned to JavaScript (all fields hex-encoded).
 */
export class WasmEncryptedKey {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmEncryptedKey.prototype);
        obj.__wbg_ptr = ptr;
        WasmEncryptedKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmEncryptedKeyFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmencryptedkey_free(ptr, 0);
    }
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     * @returns {string}
     */
    get encryptedKey() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmencryptedkey_encryptedKey(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Hex-encoded 24-byte nonce.
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmencryptedkey_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Hex-encoded 16-byte salt.
     * @returns {string}
     */
    get salt() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmencryptedkey_salt(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     * @param {string} arg0
     */
    set encryptedKey(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmencryptedkey_encryptedKey(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Hex-encoded 24-byte nonce.
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmencryptedkey_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Hex-encoded 16-byte salt.
     * @param {string} arg0
     */
    set salt(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmencryptedkey_salt(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmEncryptedKey.prototype[Symbol.dispose] = WasmEncryptedKey.prototype.free;

/**
 * Encrypted payload returned to JavaScript (all fields hex-encoded).
 */
export class WasmEncryptedPayload {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmEncryptedPayload.prototype);
        obj.__wbg_ptr = ptr;
        WasmEncryptedPayloadFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmEncryptedPayloadFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmencryptedpayload_free(ptr, 0);
    }
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     * @returns {string}
     */
    get ciphertext() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmencryptedpayload_ciphertext(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Hex-encoded 24-byte nonce.
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmencryptedpayload_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Hex-encoded ciphertext (includes Poly1305 tag).
     * @param {string} arg0
     */
    set ciphertext(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmencryptedkey_salt(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Hex-encoded 24-byte nonce.
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmencryptedkey_nonce(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmEncryptedPayload.prototype[Symbol.dispose] = WasmEncryptedPayload.prototype.free;

/**
 * Parameters for generating a fund proof.
 */
export class WasmFundParams {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmFundParams.prototype);
        obj.__wbg_ptr = ptr;
        WasmFundParamsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmFundParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmfundparams_free(ptr, 0);
    }
    /**
     * Amount to deposit (string for large numbers)
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Optional auditor public key (hex, concatenated x||y)
     * @returns {string | undefined}
     */
    get auditor_public_key() {
        const ret = wasm.__wbg_get_wasmfundparams_auditor_public_key(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Chain ID (hex)
     * @returns {string}
     */
    get chain_id() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_chain_id(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Current balance ciphertext
     * @returns {string}
     */
    get current_cipher_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_current_cipher_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_current_cipher_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_current_cipher_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_current_cipher_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transaction nonce (hex)
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sender address (hex) - from get_caller_address()
     * @returns {string}
     */
    get sender_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_sender_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Tongo contract address (hex)
     * @returns {string}
     */
    get tongo_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundparams_tongo_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Amount to deposit (string for large numbers)
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Optional auditor public key (hex, concatenated x||y)
     * @param {string | null} [arg0]
     */
    set auditor_public_key(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_auditor_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Chain ID (hex)
     * @param {string} arg0
     */
    set chain_id(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Current balance ciphertext
     * @param {string} arg0
     */
    set current_cipher_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transaction nonce (hex)
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sender address (hex) - from get_caller_address()
     * @param {string} arg0
     */
    set sender_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Tongo contract address (hex)
     * @param {string} arg0
     */
    set tongo_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} amount
     * @param {string} nonce
     * @param {string} chain_id
     * @param {string} tongo_address
     * @param {string} sender_address
     * @param {string} current_cipher_l_x
     * @param {string} current_cipher_l_y
     * @param {string} current_cipher_r_x
     * @param {string} current_cipher_r_y
     */
    constructor(amount, nonce, chain_id, tongo_address, sender_address, current_cipher_l_x, current_cipher_l_y, current_cipher_r_x, current_cipher_r_y) {
        const ptr0 = passStringToWasm0(amount, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(tongo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(current_cipher_l_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(current_cipher_l_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(current_cipher_r_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(current_cipher_r_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        const ret = wasm.wasmfundparams_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8);
        this.__wbg_ptr = ret >>> 0;
        WasmFundParamsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} auditor_public_key
     * @returns {WasmFundParams}
     */
    withAuditor(auditor_public_key) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passStringToWasm0(auditor_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmfundparams_withAuditor(ptr, ptr0, len0);
        return WasmFundParams.__wrap(ret);
    }
}
if (Symbol.dispose) WasmFundParams.prototype[Symbol.dispose] = WasmFundParams.prototype.free;

/**
 * Result of a fund proof generation.
 */
export class WasmFundProofResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmFundProofResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmFundProofResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmFundProofResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmfundproofresult_free(ptr, 0);
    }
    /**
     * Amount funded
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundproofresult_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @returns {string | undefined}
     */
    get audit_json() {
        const ret = wasm.__wbg_get_wasmfundproofresult_audit_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * PoE proof as JSON
     * @returns {string}
     */
    get proof_json() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundproofresult_proof_json(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y point (x coordinate)
     * @returns {string}
     */
    get y_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundproofresult_y_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y point (y coordinate)
     * @returns {string}
     */
    get y_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmfundproofresult_y_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Amount funded
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @param {string | null} [arg0]
     */
    set audit_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundproofresult_audit_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * PoE proof as JSON
     * @param {string} arg0
     */
    set proof_json(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y point (x coordinate)
     * @param {string} arg0
     */
    set y_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y point (y coordinate)
     * @param {string} arg0
     */
    set y_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmFundProofResult.prototype[Symbol.dispose] = WasmFundProofResult.prototype.free;

/**
 * Keypair for Tongo operations.
 */
export class WasmKeypair {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmKeypair.prototype);
        obj.__wbg_ptr = ptr;
        WasmKeypairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmKeypairFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmkeypair_free(ptr, 0);
    }
    /**
     * Private key as hex string (0x-prefixed)
     * @returns {string}
     */
    get private_key() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmkeypair_private_key(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key X coordinate as hex string
     * @returns {string}
     */
    get public_key_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmkeypair_public_key_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y coordinate as hex string
     * @returns {string}
     */
    get public_key_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmkeypair_public_key_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Private key as hex string (0x-prefixed)
     * @param {string} arg0
     */
    set private_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key X coordinate as hex string
     * @param {string} arg0
     */
    set public_key_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y coordinate as hex string
     * @param {string} arg0
     */
    set public_key_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmaccountstate_pending_balance(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} private_key
     * @param {string} public_key_x
     * @param {string} public_key_y
     */
    constructor(private_key, public_key_x, public_key_y) {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(public_key_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(public_key_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.wasmkeypair_new(ptr0, len0, ptr1, len1, ptr2, len2);
        this.__wbg_ptr = ret >>> 0;
        WasmKeypairFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get the full public key as "0x{x}{y}" concatenated hex.
     * @returns {string}
     */
    publicKeyHex() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmkeypair_publicKeyHex(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) WasmKeypair.prototype[Symbol.dispose] = WasmKeypair.prototype.free;

/**
 * Nostr keypair (secp256k1, x-only public key).
 *
 * Used for NIP-04/NIP-44 encrypted messaging.
 * Public key is x-only (32 bytes, BIP-340 format).
 */
export class WasmNostrKeypair {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmNostrKeypair.prototype);
        obj.__wbg_ptr = ptr;
        WasmNostrKeypairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmNostrKeypairFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmnostrkeypair_free(ptr, 0);
    }
    /**
     * Private key as hex string (64 hex chars, no 0x prefix)
     * @returns {string}
     */
    get private_key() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmnostrkeypair_private_key(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key as x-only hex string (64 hex chars, no 0x prefix)
     * @returns {string}
     */
    get public_key() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmnostrkeypair_public_key(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Private key as hex string (64 hex chars, no 0x prefix)
     * @param {string} arg0
     */
    set private_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key as x-only hex string (64 hex chars, no 0x prefix)
     * @param {string} arg0
     */
    set public_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} private_key
     * @param {string} public_key
     */
    constructor(private_key, public_key) {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmnostrkeypair_new(ptr0, len0, ptr1, len1);
        this.__wbg_ptr = ret >>> 0;
        WasmNostrKeypairFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmNostrKeypair.prototype[Symbol.dispose] = WasmNostrKeypair.prototype.free;

/**
 * Nostr BIP-340 Schnorr signature result.
 */
export class WasmNostrSignature {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmNostrSignature.prototype);
        obj.__wbg_ptr = ptr;
        WasmNostrSignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmNostrSignatureFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmnostrsignature_free(ptr, 0);
    }
    /**
     * x-only public key (64 hex chars, no 0x prefix)
     * @returns {string}
     */
    get publicKey() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmnostrsignature_publicKey(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * BIP-340 signature (128 hex chars, no 0x prefix)
     * @returns {string}
     */
    get signature() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmnostrsignature_signature(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * x-only public key (64 hex chars, no 0x prefix)
     * @param {string} arg0
     */
    set publicKey(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * BIP-340 signature (128 hex chars, no 0x prefix)
     * @param {string} arg0
     */
    set signature(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmNostrSignature.prototype[Symbol.dispose] = WasmNostrSignature.prototype.free;

/**
 * Point on the Stark curve (serialized as hex strings).
 */
export class WasmPoint {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmPoint.prototype);
        obj.__wbg_ptr = ptr;
        WasmPointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmPointFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmpoint_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmpoint_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmpoint_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {string} arg0
     */
    set x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} x
     * @param {string} y
     */
    constructor(x, y) {
        const ptr0 = passStringToWasm0(x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.wasmpoint_new(ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        WasmPointFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmPoint.prototype[Symbol.dispose] = WasmPoint.prototype.free;

/**
 * Parameters for generating a ragequit proof.
 */
export class WasmRagequitParams {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRagequitParams.prototype);
        obj.__wbg_ptr = ptr;
        WasmRagequitParamsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRagequitParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmragequitparams_free(ptr, 0);
    }
    /**
     * Optional auditor public key
     * @returns {string | undefined}
     */
    get auditor_public_key() {
        const ret = wasm.__wbg_get_wasmragequitparams_auditor_public_key(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Chain ID (hex)
     * @returns {string}
     */
    get chain_id() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_chain_id(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Current balance ciphertext
     * @returns {string}
     */
    get current_cipher_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_current_cipher_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_current_cipher_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_current_cipher_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_current_cipher_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transaction nonce (hex)
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Recipient address for withdrawn funds (hex)
     * @returns {string}
     */
    get recipient_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_recipient_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sender address (hex)
     * @returns {string}
     */
    get sender_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_sender_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Tongo contract address (hex)
     * @returns {string}
     */
    get tongo_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitparams_tongo_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Optional auditor public key
     * @param {string | null} [arg0]
     */
    set auditor_public_key(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_auditor_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Chain ID (hex)
     * @param {string} arg0
     */
    set chain_id(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Current balance ciphertext
     * @param {string} arg0
     */
    set current_cipher_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transaction nonce (hex)
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Recipient address for withdrawn funds (hex)
     * @param {string} arg0
     */
    set recipient_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sender address (hex)
     * @param {string} arg0
     */
    set sender_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Tongo contract address (hex)
     * @param {string} arg0
     */
    set tongo_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} recipient_address
     * @param {string} nonce
     * @param {string} chain_id
     * @param {string} tongo_address
     * @param {string} sender_address
     * @param {string} current_cipher_l_x
     * @param {string} current_cipher_l_y
     * @param {string} current_cipher_r_x
     * @param {string} current_cipher_r_y
     */
    constructor(recipient_address, nonce, chain_id, tongo_address, sender_address, current_cipher_l_x, current_cipher_l_y, current_cipher_r_x, current_cipher_r_y) {
        const ptr0 = passStringToWasm0(recipient_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(tongo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(current_cipher_l_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(current_cipher_l_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(current_cipher_r_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(current_cipher_r_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        const ret = wasm.wasmfundparams_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8);
        this.__wbg_ptr = ret >>> 0;
        WasmRagequitParamsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} auditor_public_key
     * @returns {WasmRagequitParams}
     */
    withAuditor(auditor_public_key) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passStringToWasm0(auditor_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmfundparams_withAuditor(ptr, ptr0, len0);
        return WasmRagequitParams.__wrap(ret);
    }
}
if (Symbol.dispose) WasmRagequitParams.prototype[Symbol.dispose] = WasmRagequitParams.prototype.free;

/**
 * Result of a ragequit proof generation.
 */
export class WasmRagequitProofResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRagequitProofResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmRagequitProofResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRagequitProofResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmragequitproofresult_free(ptr, 0);
    }
    /**
     * Commitment A_r = R0^kx
     * @returns {string}
     */
    get a_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_a_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_a_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Commitment A_x = g^kx
     * @returns {string}
     */
    get a_x_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_a_x_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_x_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_a_x_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Full balance amount
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @returns {string | undefined}
     */
    get audit_json() {
        const ret = wasm.__wbg_get_wasmragequitproofresult_audit_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Recipient address
     * @returns {string}
     */
    get recipient() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_recipient(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Scalar response sx
     * @returns {string}
     */
    get sx() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_sx(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y point
     * @returns {string}
     */
    get y_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_y_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get y_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmragequitproofresult_y_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Commitment A_r = R0^kx
     * @param {string} arg0
     */
    set a_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Commitment A_x = g^kx
     * @param {string} arg0
     */
    set a_x_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_x_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Full balance amount
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @param {string | null} [arg0]
     */
    set audit_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_auditor_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Recipient address
     * @param {string} arg0
     */
    set recipient(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Scalar response sx
     * @param {string} arg0
     */
    set sx(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y point
     * @param {string} arg0
     */
    set y_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set y_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmRagequitProofResult.prototype[Symbol.dispose] = WasmRagequitProofResult.prototype.free;

/**
 * Parameters for generating a rollover proof.
 */
export class WasmRolloverParams {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRolloverParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmrolloverparams_free(ptr, 0);
    }
    /**
     * Chain ID (hex)
     * @returns {string}
     */
    get chain_id() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverparams_chain_id(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transaction nonce (hex)
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverparams_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sender address (hex)
     * @returns {string}
     */
    get sender_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverparams_sender_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Tongo contract address (hex)
     * @returns {string}
     */
    get tongo_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverparams_tongo_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Chain ID (hex)
     * @param {string} arg0
     */
    set chain_id(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transaction nonce (hex)
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sender address (hex)
     * @param {string} arg0
     */
    set sender_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Tongo contract address (hex)
     * @param {string} arg0
     */
    set tongo_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} nonce
     * @param {string} chain_id
     * @param {string} tongo_address
     * @param {string} sender_address
     */
    constructor(nonce, chain_id, tongo_address, sender_address) {
        const ptr0 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(tongo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.wasmrolloverparams_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        this.__wbg_ptr = ret >>> 0;
        WasmRolloverParamsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
}
if (Symbol.dispose) WasmRolloverParams.prototype[Symbol.dispose] = WasmRolloverParams.prototype.free;

/**
 * Result of a rollover proof generation.
 */
export class WasmRolloverProofResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRolloverProofResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmRolloverProofResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRolloverProofResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmrolloverproofresult_free(ptr, 0);
    }
    /**
     * Pending amount that was rolled over
     * @returns {string}
     */
    get pending_amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverproofresult_pending_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * PoE proof as JSON
     * @returns {string}
     */
    get proof_json() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverproofresult_proof_json(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y point
     * @returns {string}
     */
    get y_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverproofresult_y_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get y_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmrolloverproofresult_y_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Pending amount that was rolled over
     * @param {string} arg0
     */
    set pending_amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * PoE proof as JSON
     * @param {string} arg0
     */
    set proof_json(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y point
     * @param {string} arg0
     */
    set y_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set y_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmRolloverProofResult.prototype[Symbol.dispose] = WasmRolloverProofResult.prototype.free;

/**
 * Stark ECDSA signature result.
 */
export class WasmStarkSignature {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmStarkSignature.prototype);
        obj.__wbg_ptr = ptr;
        WasmStarkSignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmStarkSignatureFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmstarksignature_free(ptr, 0);
    }
    /**
     * Public key (hex)
     * @returns {string}
     */
    get publicKey() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmstarksignature_publicKey(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Signature r component (hex)
     * @returns {string}
     */
    get r() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmstarksignature_r(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Signature s component (hex)
     * @returns {string}
     */
    get s() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmstarksignature_s(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key (hex)
     * @param {string} arg0
     */
    set publicKey(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmaccountstate_pending_balance(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Signature r component (hex)
     * @param {string} arg0
     */
    set r(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Signature s component (hex)
     * @param {string} arg0
     */
    set s(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmciphertext_l_y(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmStarkSignature.prototype[Symbol.dispose] = WasmStarkSignature.prototype.free;

/**
 * Parameters for generating a transfer proof.
 */
export class WasmTransferParams {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmTransferParams.prototype);
        obj.__wbg_ptr = ptr;
        WasmTransferParamsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmTransferParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmtransferparams_free(ptr, 0);
    }
    /**
     * Amount to transfer
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Optional auditor public key
     * @returns {string | undefined}
     */
    get auditor_public_key() {
        const ret = wasm.__wbg_get_wasmtransferparams_auditor_public_key(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Bit size for range proof (default: 40)
     * @returns {number | undefined}
     */
    get bit_size() {
        const ret = wasm.__wbg_get_wasmtransferparams_bit_size(this.__wbg_ptr);
        return ret === 0xFFFFFF ? undefined : ret;
    }
    /**
     * Chain ID (hex)
     * @returns {string}
     */
    get chain_id() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_chain_id(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Current balance ciphertext
     * @returns {string}
     */
    get current_cipher_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_current_cipher_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_current_cipher_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_current_cipher_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_current_cipher_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transaction nonce (hex)
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Recipient's Tongo public key
     * @returns {string}
     */
    get recipient_public_key() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_recipient_public_key(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sender address (hex)
     * @returns {string}
     */
    get sender_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_sender_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Tongo contract address (hex)
     * @returns {string}
     */
    get tongo_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferparams_tongo_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Amount to transfer
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Optional auditor public key
     * @param {string | null} [arg0]
     */
    set auditor_public_key(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_auditor_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Bit size for range proof (default: 40)
     * @param {number | null} [arg0]
     */
    set bit_size(arg0) {
        wasm.__wbg_set_wasmtransferparams_bit_size(this.__wbg_ptr, isLikeNone(arg0) ? 0xFFFFFF : arg0);
    }
    /**
     * Chain ID (hex)
     * @param {string} arg0
     */
    set chain_id(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Current balance ciphertext
     * @param {string} arg0
     */
    set current_cipher_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transaction nonce (hex)
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Recipient's Tongo public key
     * @param {string} arg0
     */
    set recipient_public_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sender address (hex)
     * @param {string} arg0
     */
    set sender_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Tongo contract address (hex)
     * @param {string} arg0
     */
    set tongo_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} recipient_public_key
     * @param {string} amount
     * @param {string} nonce
     * @param {string} chain_id
     * @param {string} tongo_address
     * @param {string} sender_address
     * @param {string} current_cipher_l_x
     * @param {string} current_cipher_l_y
     * @param {string} current_cipher_r_x
     * @param {string} current_cipher_r_y
     */
    constructor(recipient_public_key, amount, nonce, chain_id, tongo_address, sender_address, current_cipher_l_x, current_cipher_l_y, current_cipher_r_x, current_cipher_r_y) {
        const ptr0 = passStringToWasm0(recipient_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(amount, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(tongo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(current_cipher_l_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(current_cipher_l_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(current_cipher_r_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        const ptr9 = passStringToWasm0(current_cipher_r_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len9 = WASM_VECTOR_LEN;
        const ret = wasm.wasmtransferparams_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, ptr9, len9);
        this.__wbg_ptr = ret >>> 0;
        WasmTransferParamsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} auditor_public_key
     * @returns {WasmTransferParams}
     */
    withAuditor(auditor_public_key) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passStringToWasm0(auditor_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmtransferparams_withAuditor(ptr, ptr0, len0);
        return WasmTransferParams.__wrap(ret);
    }
    /**
     * @param {number} bit_size
     * @returns {WasmTransferParams}
     */
    withBitSize(bit_size) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.wasmtransferparams_withBitSize(ptr, bit_size);
        return WasmTransferParams.__wrap(ret);
    }
}
if (Symbol.dispose) WasmTransferParams.prototype[Symbol.dispose] = WasmTransferParams.prototype.free;

/**
 * Result of a transfer proof generation.
 */
export class WasmTransferProofResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmTransferProofResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmTransferProofResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmTransferProofResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmtransferproofresult_free(ptr, 0);
    }
    /**
     * Audit for balance (if auditor configured)
     * @returns {string | undefined}
     */
    get audit_balance_json() {
        const ret = wasm.__wbg_get_wasmtransferproofresult_audit_balance_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Audit for transfer (if auditor configured)
     * @returns {string | undefined}
     */
    get audit_transfer_json() {
        const ret = wasm.__wbg_get_wasmtransferproofresult_audit_transfer_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Auxiliar cipher 2 (R_aux2 = g^r2)
     * @returns {string}
     */
    get aux2_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux2_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux2_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux2_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Auxiliar cipher 2 (V2 = g^b_left*h^r2)
     * @returns {string}
     */
    get aux2_v_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux2_v_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux2_v_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux2_v_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Auxiliar cipher (R_aux = g^r)
     * @returns {string}
     */
    get aux_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Auxiliar cipher (V = g^b*h^r)
     * @returns {string}
     */
    get aux_v_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux_v_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux_v_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_aux_v_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * New balance cipher (L)
     * @returns {string}
     */
    get new_balance_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_new_balance_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get new_balance_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_new_balance_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * New balance cipher (R)
     * @returns {string}
     */
    get new_balance_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_new_balance_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get new_balance_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_new_balance_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Complete transfer proof as JSON
     * @returns {string}
     */
    get proof_json() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_proof_json(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transfer cipher for self (L)
     * @returns {string}
     */
    get self_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_self_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get self_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_self_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transfer cipher for self (R)
     * @returns {string}
     */
    get self_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_self_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get self_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_self_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transfer cipher for recipient (L)
     * @returns {string}
     */
    get transfer_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_transfer_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get transfer_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_transfer_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transfer cipher for recipient (R)
     * @returns {string}
     */
    get transfer_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_transfer_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get transfer_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmtransferproofresult_transfer_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Audit for balance (if auditor configured)
     * @param {string | null} [arg0]
     */
    set audit_balance_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_audit_balance_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Audit for transfer (if auditor configured)
     * @param {string | null} [arg0]
     */
    set audit_transfer_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_audit_transfer_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher 2 (R_aux2 = g^r2)
     * @param {string} arg0
     */
    set aux2_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux2_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher 2 (V2 = g^b_left*h^r2)
     * @param {string} arg0
     */
    set aux2_v_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_v_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux2_v_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_v_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher (R_aux = g^r)
     * @param {string} arg0
     */
    set aux_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher (V = g^b*h^r)
     * @param {string} arg0
     */
    set aux_v_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux_v_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * New balance cipher (L)
     * @param {string} arg0
     */
    set new_balance_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set new_balance_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * New balance cipher (R)
     * @param {string} arg0
     */
    set new_balance_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set new_balance_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Complete transfer proof as JSON
     * @param {string} arg0
     */
    set proof_json(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_proof_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transfer cipher for self (L)
     * @param {string} arg0
     */
    set self_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set self_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transfer cipher for self (R)
     * @param {string} arg0
     */
    set self_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set self_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transfer cipher for recipient (L)
     * @param {string} arg0
     */
    set transfer_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set transfer_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transfer cipher for recipient (R)
     * @param {string} arg0
     */
    set transfer_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set transfer_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmTransferProofResult.prototype[Symbol.dispose] = WasmTransferProofResult.prototype.free;

/**
 * Transaction type enum for Tongo operations.
 * @enum {0 | 1 | 2 | 3 | 4}
 */
export const WasmTxType = Object.freeze({
    Fund: 0, "0": "Fund",
    Transfer: 1, "1": "Transfer",
    Rollover: 2, "2": "Rollover",
    Withdraw: 3, "3": "Withdraw",
    Ragequit: 4, "4": "Ragequit",
});

/**
 * Parameters for generating a withdraw proof.
 */
export class WasmWithdrawParams {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmWithdrawParams.prototype);
        obj.__wbg_ptr = ptr;
        WasmWithdrawParamsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmWithdrawParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmwithdrawparams_free(ptr, 0);
    }
    /**
     * Amount to withdraw
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Optional auditor public key
     * @returns {string | undefined}
     */
    get auditor_public_key() {
        const ret = wasm.__wbg_get_wasmwithdrawparams_auditor_public_key(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Bit size for range proof (default: 40)
     * @returns {number | undefined}
     */
    get bit_size() {
        const ret = wasm.__wbg_get_wasmtransferparams_bit_size(this.__wbg_ptr);
        return ret === 0xFFFFFF ? undefined : ret;
    }
    /**
     * Chain ID (hex)
     * @returns {string}
     */
    get chain_id() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_chain_id(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Current balance ciphertext
     * @returns {string}
     */
    get current_cipher_l_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_current_cipher_l_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_l_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_current_cipher_l_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_current_cipher_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get current_cipher_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_current_cipher_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Transaction nonce (hex)
     * @returns {string}
     */
    get nonce() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_nonce(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Recipient address for withdrawn funds (hex)
     * @returns {string}
     */
    get recipient_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_recipient_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Sender address (hex)
     * @returns {string}
     */
    get sender_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_sender_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Tongo contract address (hex)
     * @returns {string}
     */
    get tongo_address() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawparams_tongo_address(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Amount to withdraw
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Optional auditor public key
     * @param {string | null} [arg0]
     */
    set auditor_public_key(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_auditor_public_key(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Bit size for range proof (default: 40)
     * @param {number | null} [arg0]
     */
    set bit_size(arg0) {
        wasm.__wbg_set_wasmtransferparams_bit_size(this.__wbg_ptr, isLikeNone(arg0) ? 0xFFFFFF : arg0);
    }
    /**
     * Chain ID (hex)
     * @param {string} arg0
     */
    set chain_id(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Current balance ciphertext
     * @param {string} arg0
     */
    set current_cipher_l_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_l_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set current_cipher_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Transaction nonce (hex)
     * @param {string} arg0
     */
    set nonce(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Recipient address for withdrawn funds (hex)
     * @param {string} arg0
     */
    set recipient_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Sender address (hex)
     * @param {string} arg0
     */
    set sender_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Tongo contract address (hex)
     * @param {string} arg0
     */
    set tongo_address(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} recipient_address
     * @param {string} amount
     * @param {string} nonce
     * @param {string} chain_id
     * @param {string} tongo_address
     * @param {string} sender_address
     * @param {string} current_cipher_l_x
     * @param {string} current_cipher_l_y
     * @param {string} current_cipher_r_x
     * @param {string} current_cipher_r_y
     */
    constructor(recipient_address, amount, nonce, chain_id, tongo_address, sender_address, current_cipher_l_x, current_cipher_l_y, current_cipher_r_x, current_cipher_r_y) {
        const ptr0 = passStringToWasm0(recipient_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(amount, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(tongo_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(current_cipher_l_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(current_cipher_l_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ptr8 = passStringToWasm0(current_cipher_r_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len8 = WASM_VECTOR_LEN;
        const ptr9 = passStringToWasm0(current_cipher_r_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len9 = WASM_VECTOR_LEN;
        const ret = wasm.wasmtransferparams_new(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8, ptr9, len9);
        this.__wbg_ptr = ret >>> 0;
        WasmWithdrawParamsFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} auditor_public_key
     * @returns {WasmWithdrawParams}
     */
    withAuditor(auditor_public_key) {
        const ptr = this.__destroy_into_raw();
        const ptr0 = passStringToWasm0(auditor_public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmtransferparams_withAuditor(ptr, ptr0, len0);
        return WasmWithdrawParams.__wrap(ret);
    }
    /**
     * @param {number} bit_size
     * @returns {WasmWithdrawParams}
     */
    withBitSize(bit_size) {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.wasmtransferparams_withBitSize(ptr, bit_size);
        return WasmWithdrawParams.__wrap(ret);
    }
}
if (Symbol.dispose) WasmWithdrawParams.prototype[Symbol.dispose] = WasmWithdrawParams.prototype.free;

/**
 * Result of a withdraw proof generation.
 */
export class WasmWithdrawProofResult {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmWithdrawProofResult.prototype);
        obj.__wbg_ptr = ptr;
        WasmWithdrawProofResultFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmWithdrawProofResultFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmwithdrawproofresult_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get a_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_v_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_v_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_v_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_v_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_x2() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_x2(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Commitments
     * @returns {string}
     */
    get a_x_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_x_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_x_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_x_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get a_y2() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_a_y2(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Amount withdrawn
     * @returns {string}
     */
    get amount() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_amount(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @returns {string | undefined}
     */
    get audit_json() {
        const ret = wasm.__wbg_get_wasmwithdrawproofresult_audit_json(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Auxiliar cipher (R_aux = g^r)
     * @returns {string}
     */
    get aux_r_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_aux_r_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux_r_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_aux_r_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Auxiliar cipher (V = g^b_left*h^r)
     * @returns {string}
     */
    get aux_v_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_aux_v_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get aux_v_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_aux_v_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Range proof as JSON
     * @returns {string}
     */
    get range_json() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_range_json(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Recipient address
     * @returns {string}
     */
    get recipient() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_recipient(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get sb() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_sb(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get sr() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_sr(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Scalar responses
     * @returns {string}
     */
    get sx() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_sx(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Public key Y point
     * @returns {string}
     */
    get y_x() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_y_x(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    get y_y() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_wasmwithdrawproofresult_y_y(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {string} arg0
     */
    set a_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_sender_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_v_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_v_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferparams_current_cipher_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_x2(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Commitments
     * @param {string} arg0
     */
    set a_x_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_chain_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_x_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_tongo_address(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set a_y2(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_current_cipher_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Amount withdrawn
     * @param {string} arg0
     */
    set amount(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Audit data as JSON (if auditor configured)
     * @param {string | null} [arg0]
     */
    set audit_json(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmwithdrawproofresult_audit_json(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher (R_aux = g^r)
     * @param {string} arg0
     */
    set aux_r_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux_r_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_l_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Auxiliar cipher (V = g^b_left*h^r)
     * @param {string} arg0
     */
    set aux_v_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_v_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set aux_v_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Range proof as JSON
     * @param {string} arg0
     */
    set range_json(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_l_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Recipient address
     * @param {string} arg0
     */
    set recipient(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_new_balance_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set sb(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux_r_y(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set sr(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux2_v_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Scalar responses
     * @param {string} arg0
     */
    set sx(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmtransferproofresult_aux_r_x(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Public key Y point
     * @param {string} arg0
     */
    set y_x(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_amount(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {string} arg0
     */
    set y_y(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_wasmfundparams_nonce(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) WasmWithdrawProofResult.prototype[Symbol.dispose] = WasmWithdrawProofResult.prototype.free;

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
 * @param {string} salt
 * @param {string} class_hash
 * @param {string[]} constructor_calldata
 * @param {string} deployer_address
 * @returns {string}
 */
export function calculateContractAddress(salt, class_hash, constructor_calldata, deployer_address) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArrayJsValueToWasm0(constructor_calldata, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(deployer_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.calculateContractAddress(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

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
 * @param {string} calls_json
 * @returns {string[]}
 */
export function compileCalls(calls_json) {
    const ptr0 = passStringToWasm0(calls_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.compileCalls(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return v2;
}

/**
 * Compute the hash of a declare transaction (v2).
 * @param {string} sender_address
 * @param {string} class_hash
 * @param {string} max_fee
 * @param {string} chain_id
 * @param {string} nonce
 * @param {string} compiled_class_hash
 * @returns {string}
 */
export function computeDeclareTransactionHashV2(sender_address, class_hash, max_fee, chain_id, nonce, compiled_class_hash) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(max_fee, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(compiled_class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.computeDeclareTransactionHashV2(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Compute the hash of a declare transaction (v3).
 * @param {string} sender_address
 * @param {string} class_hash
 * @param {string} chain_id
 * @param {string} nonce
 * @param {string} compiled_class_hash
 * @param {string} tip
 * @param {any} resource_bounds
 * @param {string[]} paymaster_data
 * @param {number} nonce_data_availability_mode
 * @param {number} fee_data_availability_mode
 * @param {string[]} account_deployment_data
 * @returns {string}
 */
export function computeDeclareTransactionHashV3(sender_address, class_hash, chain_id, nonce, compiled_class_hash, tip, resource_bounds, paymaster_data, nonce_data_availability_mode, fee_data_availability_mode, account_deployment_data) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(compiled_class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(tip, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passArrayJsValueToWasm0(paymaster_data, wasm.__wbindgen_malloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passArrayJsValueToWasm0(account_deployment_data, wasm.__wbindgen_malloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.computeDeclareTransactionHashV3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, resource_bounds, ptr6, len6, nonce_data_availability_mode, fee_data_availability_mode, ptr7, len7);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * Compute the hash of a deploy account transaction (v1).
 * @param {string} contract_address
 * @param {string} class_hash
 * @param {string[]} constructor_calldata
 * @param {string} salt
 * @param {string} max_fee
 * @param {string} chain_id
 * @param {string} nonce
 * @returns {string}
 */
export function computeDeployAccountTransactionHashV1(contract_address, class_hash, constructor_calldata, salt, max_fee, chain_id, nonce) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(contract_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArrayJsValueToWasm0(constructor_calldata, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(max_fee, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ret = wasm.computeDeployAccountTransactionHashV1(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6);
        var ptr8 = ret[0];
        var len8 = ret[1];
        if (ret[3]) {
            ptr8 = 0; len8 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred9_0 = ptr8;
        deferred9_1 = len8;
        return getStringFromWasm0(ptr8, len8);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

/**
 * Compute the hash of a deploy account transaction (v3).
 * @param {string} contract_address
 * @param {string} class_hash
 * @param {string[]} constructor_calldata
 * @param {string} salt
 * @param {string} chain_id
 * @param {string} nonce
 * @param {string} tip
 * @param {any} resource_bounds
 * @param {string[]} paymaster_data
 * @param {number} nonce_data_availability_mode
 * @param {number} fee_data_availability_mode
 * @returns {string}
 */
export function computeDeployAccountTransactionHashV3(contract_address, class_hash, constructor_calldata, salt, chain_id, nonce, tip, resource_bounds, paymaster_data, nonce_data_availability_mode, fee_data_availability_mode) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(contract_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArrayJsValueToWasm0(constructor_calldata, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(tip, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passArrayJsValueToWasm0(paymaster_data, wasm.__wbindgen_malloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.computeDeployAccountTransactionHashV3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, resource_bounds, ptr7, len7, nonce_data_availability_mode, fee_data_availability_mode);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * Compute the hash of an invoke transaction (v1).
 *
 * All felt arguments are hex strings (e.g. `"0x1234"`).
 * @param {string} sender_address
 * @param {string[]} calldata
 * @param {string} max_fee
 * @param {string} chain_id
 * @param {string} nonce
 * @returns {string}
 */
export function computeInvokeTransactionHashV1(sender_address, calldata, max_fee, chain_id, nonce) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArrayJsValueToWasm0(calldata, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(max_fee, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.computeInvokeTransactionHashV1(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Compute the hash of an invoke transaction (v3).
 * @param {string} sender_address
 * @param {string[]} calldata
 * @param {string} chain_id
 * @param {string} nonce
 * @param {string} tip
 * @param {any} resource_bounds
 * @param {string[]} paymaster_data
 * @param {number} nonce_data_availability_mode
 * @param {number} fee_data_availability_mode
 * @param {string[]} account_deployment_data
 * @param {string[] | null} [proof_facts]
 * @returns {string}
 */
export function computeInvokeTransactionHashV3(sender_address, calldata, chain_id, nonce, tip, resource_bounds, paymaster_data, nonce_data_availability_mode, fee_data_availability_mode, account_deployment_data, proof_facts) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArrayJsValueToWasm0(calldata, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(chain_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(tip, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArrayJsValueToWasm0(paymaster_data, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passArrayJsValueToWasm0(account_deployment_data, wasm.__wbindgen_malloc);
        const len6 = WASM_VECTOR_LEN;
        var ptr7 = isLikeNone(proof_facts) ? 0 : passArrayJsValueToWasm0(proof_facts, wasm.__wbindgen_malloc);
        var len7 = WASM_VECTOR_LEN;
        const ret = wasm.computeInvokeTransactionHashV3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, resource_bounds, ptr5, len5, nonce_data_availability_mode, fee_data_availability_mode, ptr6, len6, ptr7, len7);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * Compute the SNIP-12 typed data message hash.
 *
 * # Arguments
 * * `typed_data_json` - JSON string conforming to the SNIP-12 typed data schema.
 * * `account_address` - Hex-encoded Starknet account address.
 *
 * # Returns
 * The message hash as a hex string.
 * @param {string} typed_data_json
 * @param {string} account_address
 * @returns {string}
 */
export function computeTypedDataMessageHash(typed_data_json, account_address) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(typed_data_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(account_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.computeTypedDataMessageHash(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Decode a Cairo short-string Felt back to a UTF-8 string.
 *
 * # Arguments
 * * `felt_hex` — `0x`-prefixed hex representation of the felt.
 *
 * # Returns
 * The decoded string.
 * @param {string} felt_hex
 * @returns {string}
 */
export function decodeShortString(felt_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(felt_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.decodeShortString(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Decrypt an ethers.js / Web3 Secret Storage keystore (version 3, scrypt KDF).
 *
 * @param keystoreJson - JSON keystore string in ethers.js format
 * @param password - The password used during encryption
 * @returns Decrypted content as hex string (typically a private key)
 * @param {string} keystore_json
 * @param {string} password
 * @returns {string}
 */
export function decryptEthersKeystore(keystore_json, password) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(keystore_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.decryptEthersKeystore(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Decrypt a krusty-kms keystore (version 1) to recover the mnemonic.
 *
 * @param keystoreJson - JSON keystore string
 * @param password - The password used during encryption
 * @returns Decrypted mnemonic phrase
 * @param {string} keystore_json
 * @param {string} password
 * @returns {string}
 */
export function decryptKeystore(keystore_json, password) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(keystore_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.decryptKeystore(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Decrypt a private key that was encrypted with `encryptPrivateKey`.
 *
 * @param nonce - Hex-encoded 24-byte nonce
 * @param salt - Hex-encoded 16-byte salt
 * @param encryptedKey - Hex-encoded ciphertext
 * @param password - The password used during encryption
 * @param scryptN - The same scrypt cost parameter used during encryption
 * @returns Hex-encoded private key (no 0x prefix)
 * @param {string} nonce
 * @param {string} salt
 * @param {string} encrypted_key
 * @param {string} password
 * @param {number} scrypt_n
 * @returns {string}
 */
export function decryptPrivateKey(nonce, salt, encrypted_key, password, scrypt_n) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(encrypted_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.decryptPrivateKey(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, scrypt_n);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * Decrypt data that was encrypted with `encryptWithKey`.
 *
 * @param nonce - Hex-encoded 24-byte nonce
 * @param ciphertext - Hex-encoded ciphertext
 * @param keyHex - Hex-encoded 32-byte key (64 hex chars)
 * @returns Decrypted plaintext as a UTF-8 string
 * @param {string} nonce
 * @param {string} ciphertext
 * @param {string} key_hex
 * @returns {string}
 */
export function decryptWithKey(nonce, ciphertext, key_hex) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(nonce, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(ciphertext, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.decryptWithKey(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

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
 * @param {string} public_key
 * @param {string | null} [class_hash]
 * @returns {string}
 */
export function deriveArgentAccountAddress(public_key, class_hash) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(class_hash) ? 0 : passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.deriveArgentAccountAddress(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} mnemonic
 * @param {number} address_index
 * @param {number} account_index
 * @returns {WasmKeypair}
 */
export function deriveArgentLegacyKeypair(mnemonic, address_index, account_index) {
    const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deriveArgentLegacyKeypair(ptr0, len0, address_index, account_index);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmKeypair.__wrap(ret[0]);
}

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
 * @param {string} public_key
 * @param {string | null} [class_hash]
 * @returns {string}
 */
export function deriveBraavosAccountAddress(public_key, class_hash) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(public_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(class_hash) ? 0 : passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.deriveBraavosAccountAddress(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string} mnemonic
 * @param {number | null} [max_index]
 * @returns {string}
 */
export function deriveDiscoveryKeypairs(mnemonic, max_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.deriveDiscoveryKeypairs(ptr0, len0, isLikeNone(max_index) ? 0x100000001 : (max_index) >>> 0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Derive a keypair from mnemonic (for external use).
 * @param {string} mnemonic
 * @param {number} address_index
 * @param {number} account_index
 * @param {string | null} [passphrase]
 * @returns {WasmKeypair}
 */
export function deriveKeypair(mnemonic, address_index, account_index, passphrase) {
    const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(passphrase) ? 0 : passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.deriveKeypair(ptr0, len0, address_index, account_index, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmKeypair.__wrap(ret[0]);
}

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
 * @param {string} mnemonic
 * @param {number} address_index
 * @param {number} account_index
 * @param {string | null} [passphrase]
 * @returns {WasmNostrKeypair}
 */
export function deriveNostrKeypair(mnemonic, address_index, account_index, passphrase) {
    const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(passphrase) ? 0 : passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.deriveNostrKeypair(ptr0, len0, address_index, account_index, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmNostrKeypair.__wrap(ret[0]);
}

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
 * @param {string} public_key_x
 * @param {string} class_hash
 * @param {string | null} [salt]
 * @returns {string}
 */
export function deriveOzAccountAddress(public_key_x, class_hash, salt) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(public_key_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(class_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        var ptr2 = isLikeNone(salt) ? 0 : passStringToWasm0(salt, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len2 = WASM_VECTOR_LEN;
        const ret = wasm.deriveOzAccountAddress(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

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
 * @param {string} mnemonic
 * @param {number} address_index
 * @param {number} account_index
 * @param {string | null} [passphrase]
 * @returns {WasmKeypair}
 */
export function deriveStarknetKeypair(mnemonic, address_index, account_index, passphrase) {
    const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    var ptr1 = isLikeNone(passphrase) ? 0 : passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len1 = WASM_VECTOR_LEN;
    const ret = wasm.deriveStarknetKeypair(ptr0, len0, address_index, account_index, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmKeypair.__wrap(ret[0]);
}

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
 * @param {string} private_key
 * @returns {string}
 */
export function deriveStrk20ViewingKey(private_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.deriveStrk20ViewingKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Deserialize a public key from hex format to (x, y) coordinates.
 *
 * # Arguments
 * * `hex` - Public key in "0x{x}{y}" format (128 hex chars after 0x)
 *
 * # Returns
 * Object with x and y properties
 * @param {string} hex
 * @returns {WasmPoint}
 */
export function deserializePublicKey(hex) {
    const ptr0 = passStringToWasm0(hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.deserializePublicKey(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmPoint.__wrap(ret[0]);
}

/**
 * Perform full account discovery in a single call.
 *
 * Returns a JSON object with two fields:
 * - `keypairs`: array of DerivedKeypair objects (for API-based smart account lookup)
 * - `candidates`: array of CandidateAccount objects (for local address derivation)
 *
 * This combines `deriveDiscoveryKeypairs` and `generateAccountCandidates` into
 * a single WASM call, eliminating one JS→WASM round-trip.
 * @param {string} mnemonic
 * @param {number | null} [max_index]
 * @returns {string}
 */
export function discoverAccountsFromMnemonic(mnemonic, max_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.discoverAccountsFromMnemonic(ptr0, len0, isLikeNone(max_index) ? 0x100000001 : (max_index) >>> 0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} value
 * @returns {string}
 */
export function encodeFelt(value) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(value, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.encodeFelt(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Encode a short ASCII string (<=31 chars) as a Cairo short-string Felt.
 *
 * # Returns
 * The Felt as a `0x`-prefixed hex string.
 * @param {string} s
 * @returns {string}
 */
export function encodeShortString(s) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.encodeShortString(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Encrypt a mnemonic into a JSON keystore string (krusty-kms format, version 1).
 *
 * @param mnemonic - Mnemonic phrase to encrypt
 * @param password - Encryption password
 * @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
 * @returns JSON keystore string
 * @param {string} mnemonic
 * @param {string} password
 * @param {number} scrypt_n
 * @returns {string}
 */
export function encryptKeystore(mnemonic, password, scrypt_n) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.encryptKeystore(ptr0, len0, ptr1, len1, scrypt_n);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Encrypt a hex-encoded private key with a password (scrypt + XChaCha20-Poly1305).
 *
 * @param privateKeyHex - Private key in hex (with or without 0x prefix)
 * @param password - Encryption password
 * @param scryptN - Scrypt cost parameter N (power of 2, e.g. 32768)
 * @returns Encrypted key with hex-encoded nonce, salt, and ciphertext
 * @param {string} private_key_hex
 * @param {string} password
 * @param {number} scrypt_n
 * @returns {WasmEncryptedKey}
 */
export function encryptPrivateKey(private_key_hex, password, scrypt_n) {
    const ptr0 = passStringToWasm0(private_key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.encryptPrivateKey(ptr0, len0, ptr1, len1, scrypt_n);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmEncryptedKey.__wrap(ret[0]);
}

/**
 * Encrypt a plaintext string with a pre-derived 32-byte key.
 *
 * @param plaintext - UTF-8 string to encrypt
 * @param keyHex - Hex-encoded 32-byte key (64 hex chars)
 * @returns Encrypted payload with hex-encoded nonce and ciphertext
 * @param {string} plaintext
 * @param {string} key_hex
 * @returns {WasmEncryptedPayload}
 */
export function encryptWithKey(plaintext, key_hex) {
    const ptr0 = passStringToWasm0(plaintext, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(key_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.encryptWithKey(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmEncryptedPayload.__wrap(ret[0]);
}

/**
 * Generate a compact summary of candidate addresses grouped by derivation index.
 *
 * Returns a JSON object where keys are derivation indices and values are
 * objects mapping wallet type to address. Useful for quick discovery without
 * needing the full candidate details.
 *
 * # Returns
 * JSON string: `{ "0": { "Braavos": "0x...", "Argent": "0x...", ... }, "1": { ... } }`
 * @param {string} mnemonic
 * @param {number | null} [max_index]
 * @returns {string}
 */
export function generateAccountAddresses(mnemonic, max_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.generateAccountAddresses(ptr0, len0, isLikeNone(max_index) ? 0x100000001 : (max_index) >>> 0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {string} mnemonic
 * @param {number | null} [max_index]
 * @returns {string}
 */
export function generateAccountCandidates(mnemonic, max_index) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.generateAccountCandidates(ptr0, len0, isLikeNone(max_index) ? 0x100000001 : (max_index) >>> 0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Generate a fund (deposit) proof.
 * @param {WasmAccount} account
 * @param {WasmFundParams} params
 * @returns {WasmFundProofResult}
 */
export function generateFundProof(account, params) {
    _assertClass(account, WasmAccount);
    _assertClass(params, WasmFundParams);
    const ret = wasm.generateFundProof(account.__wbg_ptr, params.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmFundProofResult.__wrap(ret[0]);
}

/**
 * Generate a new random mnemonic phrase.
 * @param {number | null} [word_count]
 * @returns {string}
 */
export function generateMnemonic(word_count) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.generateMnemonic(isLikeNone(word_count) ? 0xFFFFFF : word_count);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate a ragequit (emergency exit) proof.
 * @param {WasmAccount} account
 * @param {WasmRagequitParams} params
 * @returns {WasmRagequitProofResult}
 */
export function generateRagequitProof(account, params) {
    _assertClass(account, WasmAccount);
    _assertClass(params, WasmRagequitParams);
    const ret = wasm.generateRagequitProof(account.__wbg_ptr, params.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmRagequitProofResult.__wrap(ret[0]);
}

/**
 * Generate a rollover proof.
 * @param {WasmAccount} account
 * @param {WasmRolloverParams} params
 * @returns {WasmRolloverProofResult}
 */
export function generateRolloverProof(account, params) {
    _assertClass(account, WasmAccount);
    _assertClass(params, WasmRolloverParams);
    const ret = wasm.generateRolloverProof(account.__wbg_ptr, params.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmRolloverProofResult.__wrap(ret[0]);
}

/**
 * Generate a transfer proof.
 * @param {WasmAccount} account
 * @param {WasmTransferParams} params
 * @returns {WasmTransferProofResult}
 */
export function generateTransferProof(account, params) {
    _assertClass(account, WasmAccount);
    _assertClass(params, WasmTransferParams);
    const ret = wasm.generateTransferProof(account.__wbg_ptr, params.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmTransferProofResult.__wrap(ret[0]);
}

/**
 * Generate a withdraw proof.
 * @param {WasmAccount} account
 * @param {WasmWithdrawParams} params
 * @returns {WasmWithdrawProofResult}
 */
export function generateWithdrawProof(account, params) {
    _assertClass(account, WasmAccount);
    _assertClass(params, WasmWithdrawParams);
    const ret = wasm.generateWithdrawProof(account.__wbg_ptr, params.__wbg_ptr);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmWithdrawProofResult.__wrap(ret[0]);
}

/**
 * Get known account class hashes for common Starknet account implementations.
 *
 * Returns a JSON string containing class hashes organized by account type
 * and version, covering OpenZeppelin, Argent, and Braavos accounts.
 *
 * # Returns
 * JSON string with nested object: `{ oz: { ... }, argent: { ... }, braavos: { ... } }`
 * @returns {string}
 */
export function getAccountClassHashes() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getAccountClassHashes();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Get build information.
 * @returns {any}
 */
export function getBuildInfo() {
    const ret = wasm.getBuildInfo();
    return ret;
}

/**
 * Get the Stark curve generator point.
 * @returns {WasmPoint}
 */
export function getGenerator() {
    const ret = wasm.getGenerator();
    return WasmPoint.__wrap(ret);
}

/**
 * Get the Nostr coin type constant (1237).
 * @returns {number}
 */
export function getNostrCoinType() {
    const ret = wasm.getNostrCoinType();
    return ret >>> 0;
}

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
 * @param {string} name
 * @returns {string}
 */
export function getSelectorFromName(name) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(name, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.getSelectorFromName(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Get the Starknet coin type constant (9004).
 * @returns {number}
 */
export function getStarknetCoinType() {
    const ret = wasm.getStarknetCoinType();
    return ret >>> 0;
}

/**
 * Get the Tongo coin type constant (5454).
 * @returns {number}
 */
export function getTongoCoinType() {
    const ret = wasm.getTongoCoinType();
    return ret >>> 0;
}

/**
 * Get the SDK version.
 * @returns {string}
 */
export function getVersion() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.getVersion();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

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
 * @param {string} seed_hex
 * @returns {string}
 */
export function grindKey(seed_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.grindKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Initialize the WASM module.
 *
 * Sets up panic hook for better error messages in console.
 * Call this before using any other functions.
 */
export function init() {
    wasm.init();
}

/**
 * Check whether a hex string is a valid Stark field element.
 *
 * # Arguments
 * * `hex_str` - Hex string to validate (with or without `0x` prefix)
 *
 * # Returns
 * `true` if the string parses as a valid felt, `false` otherwise
 * @param {string} hex_str
 * @returns {boolean}
 */
export function isValidFelt(hex_str) {
    const ptr0 = passStringToWasm0(hex_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.isValidFelt(ptr0, len0);
    return ret !== 0;
}

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
 * @param {string} hex_str
 * @returns {boolean}
 */
export function isValidStarkPrivateKey(hex_str) {
    const ptr0 = passStringToWasm0(hex_str, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.isValidStarkPrivateKey(ptr0, len0);
    return ret !== 0;
}

/**
 * Derive the x-only Nostr public key for a secp256k1 private key.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 *
 * # Returns
 * x-only public key as 64 hex chars (no 0x prefix)
 * @param {string} private_key
 * @returns {string}
 */
export function nostrPublicKey(private_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.nostrPublicKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Compute the Pedersen hash of two field elements.
 *
 * # Arguments
 * * `a` - First element as a hex string
 * * `b` - Second element as a hex string
 *
 * # Returns
 * The Pedersen hash as a hex string
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
export function pedersenHash(a, b) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(a, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(b, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.pedersenHash(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {string[]} felts
 * @returns {string}
 */
export function pedersenHashMany(felts) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArrayJsValueToWasm0(felts, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.pedersenHashMany(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Add two points on the Stark curve.
 * @param {string} p1_x
 * @param {string} p1_y
 * @param {string} p2_x
 * @param {string} p2_y
 * @returns {WasmPoint}
 */
export function pointAdd(p1_x, p1_y, p2_x, p2_y) {
    const ptr0 = passStringToWasm0(p1_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(p1_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(p2_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(p2_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.pointAdd(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmPoint.__wrap(ret[0]);
}

/**
 * Compute Poseidon hash of exactly two field elements.
 *
 * # Arguments
 * * `a` - First input (hex string)
 * * `b` - Second input (hex string)
 *
 * # Returns
 * The Poseidon hash as a hex string
 * @param {string} a
 * @param {string} b
 * @returns {string}
 */
export function poseidonHash(a, b) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(a, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(b, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.poseidonHash(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Compute a Poseidon hash of the given inputs.
 *
 * # Arguments
 * * `inputs` - Array of hex strings (felt values)
 *
 * # Returns
 * The hash as a hex string
 * @param {string[]} inputs
 * @returns {string}
 */
export function poseidonHashMany(inputs) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArrayJsValueToWasm0(inputs, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.poseidonHashMany(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

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
 * @param {number} length
 * @returns {string}
 */
export function randomBytesHex(length) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.randomBytesHex(length);
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Generate a random field element.
 * @returns {string}
 */
export function randomFelt() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.randomFelt();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

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
 * @param {string} scalar
 * @param {string} point_x
 * @param {string} point_y
 * @returns {WasmPoint}
 */
export function scalarMul(scalar, point_x, point_y) {
    const ptr0 = passStringToWasm0(scalar, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(point_x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(point_y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.scalarMul(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmPoint.__wrap(ret[0]);
}

/**
 * Multiply the generator point by a scalar.
 *
 * # Arguments
 * * `scalar` - Scalar value (hex string)
 *
 * # Returns
 * Resulting point as {x, y} object
 * @param {string} scalar
 * @returns {WasmPoint}
 */
export function scalarMulGenerator(scalar) {
    const ptr0 = passStringToWasm0(scalar, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.scalarMulGenerator(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmPoint.__wrap(ret[0]);
}

/**
 * Serialize a public key point to the standard hex format.
 *
 * # Arguments
 * * `x` - X coordinate (hex string)
 * * `y` - Y coordinate (hex string)
 *
 * # Returns
 * Concatenated "0x{x}{y}" format used by Tongo protocol
 * @param {string} x
 * @param {string} y
 * @returns {string}
 */
export function serializePublicKey(x, y) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(x, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(y, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.serializePublicKey(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Sign a 32-byte Nostr event id using BIP-340 Schnorr.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 * * `event_id` - 64 hex chars (no 0x prefix), the event id to sign
 *
 * # Returns
 * Signature result with public key and signature (both hex, no 0x prefix)
 * @param {string} private_key
 * @param {string} event_id
 * @returns {WasmNostrSignature}
 */
export function signNostrEventId(private_key, event_id) {
    const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(event_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.signNostrEventId(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmNostrSignature.__wrap(ret[0]);
}

/**
 * Sign an arbitrary message using BIP-340 Schnorr.
 *
 * # Arguments
 * * `private_key` - 64 hex chars (no 0x prefix), secp256k1 private key
 * * `message` - hex-encoded bytes (may have optional 0x prefix)
 *
 * # Returns
 * Signature result with public key and signature (both hex, no 0x prefix)
 * @param {string} private_key
 * @param {string} message
 * @returns {WasmNostrSignature}
 */
export function signNostrMessage(private_key, message) {
    const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.signNostrMessage(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmNostrSignature.__wrap(ret[0]);
}

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
 * @param {string} private_key
 * @param {string} msg_hash
 * @returns {WasmStarkSignature}
 */
export function signStarkHash(private_key, msg_hash) {
    const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(msg_hash, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.signStarkHash(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return WasmStarkSignature.__wrap(ret[0]);
}

/**
 * Derive the Stark public key corresponding to a private key.
 *
 * # Arguments
 * * `private_key` - Stark private key as hex string (0x-prefixed)
 *
 * # Returns
 * The public key as a hex string (0x-prefixed)
 * @param {string} private_key
 * @returns {string}
 */
export function starkPublicKey(private_key) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(private_key, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.starkPublicKey(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Compute Starknet keccak: Keccak-256 truncated to 250 bits.
 *
 * # Arguments
 * * `data` - Input data (interpreted according to `encoding`)
 * * `encoding` - `"hex"` to hex-decode `data`, or `"utf8"` / `None` to use raw bytes
 *
 * # Returns
 * The Starknet keccak hash as a hex string
 * @param {string} data
 * @param {string | null} [encoding]
 * @returns {string}
 */
export function starknetKeccak(data, encoding) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passStringToWasm0(data, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        var ptr1 = isLikeNone(encoding) ? 0 : passStringToWasm0(encoding, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len1 = WASM_VECTOR_LEN;
        const ret = wasm.starknetKeccak(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Validate a mnemonic phrase.
 * @param {string} mnemonic
 * @returns {boolean}
 */
export function validateMnemonic(mnemonic) {
    const ptr0 = passStringToWasm0(mnemonic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.validateMnemonic(ptr0, len0);
    return ret !== 0;
}

function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_8c4e43fe74559d73: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_String_8f0eb39a4a4c2f66: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_boolean_get_bbbb1c18aa2f5e25: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_0bc8482c6e3508ae: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_in_47fa6863be6f2f25: function(arg0, arg1) {
            const ret = arg0 in arg1;
            return ret;
        },
        __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_cd444516edc5b180: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_9e4d92534c42d778: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_jsval_loose_eq_9dd77d8cd6671811: function(arg0, arg1) {
            const ret = arg0 == arg1;
            return ret;
        },
        __wbg___wbindgen_number_get_8ff4255516ccad3e: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_string_get_72fb696202c56729: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_be289d5034ed271b: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_error_7534b8e9a36f1ab4: function(arg0, arg1) {
            let deferred0_0;
            let deferred0_1;
            try {
                deferred0_0 = arg0;
                deferred0_1 = arg1;
                console.error(getStringFromWasm0(arg0, arg1));
            } finally {
                wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
            }
        },
        __wbg_getRandomValues_1c61fac11405ffdc: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_with_ref_key_1dc361bd10053bfe: function(arg0, arg1) {
            const ret = arg0[arg1];
            return ret;
        },
        __wbg_instanceof_ArrayBuffer_c367199e2fa2aa04: function(arg0) {
            let result;
            try {
                result = arg0 instanceof ArrayBuffer;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_9b9075935c74707c: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_32ed9a279acd054c: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_new_361308b2356cecd0: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_3eb36ae241fe6f44: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_72b49615380db768: function(arg0, arg1) {
            const ret = new Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_8a6f238a6ece86ea: function() {
            const ret = new Error();
            return ret;
        },
        __wbg_new_dca287b076112a51: function() {
            const ret = new Map();
            return ret;
        },
        __wbg_new_dd2b680c8bf6ae29: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_prototypesetcall_bdcdcc5842e4d77d: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_set_1eb0999cf5d27fc8: function(arg0, arg1, arg2) {
            const ret = arg0.set(arg1, arg2);
            return ret;
        },
        __wbg_set_3f1d0b984ed272ed: function(arg0, arg1, arg2) {
            arg0[arg1] = arg2;
        },
        __wbg_set_f43e577aea94465b: function(arg0, arg1, arg2) {
            arg0[arg1 >>> 0] = arg2;
        },
        __wbg_stack_0ed75d68575b0f3c: function(arg0, arg1) {
            const ret = arg1.stack;
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbindgen_cast_0000000000000001: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `I64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0) {
            // Cast intrinsic for `U64 -> Externref`.
            const ret = BigInt.asUintN(64, arg0);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./krusty_kms_wasm_bg.js": import0,
    };
}

const WasmAccountFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmaccount_free(ptr >>> 0, 1));
const WasmAccountStateFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmaccountstate_free(ptr >>> 0, 1));
const WasmCiphertextFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmciphertext_free(ptr >>> 0, 1));
const WasmDecryptedPointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdecryptedpoint_free(ptr >>> 0, 1));
const WasmEncryptedKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmencryptedkey_free(ptr >>> 0, 1));
const WasmEncryptedPayloadFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmencryptedpayload_free(ptr >>> 0, 1));
const WasmFundParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmfundparams_free(ptr >>> 0, 1));
const WasmFundProofResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmfundproofresult_free(ptr >>> 0, 1));
const WasmKeypairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmkeypair_free(ptr >>> 0, 1));
const WasmNostrKeypairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmnostrkeypair_free(ptr >>> 0, 1));
const WasmNostrSignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmnostrsignature_free(ptr >>> 0, 1));
const WasmPointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmpoint_free(ptr >>> 0, 1));
const WasmRagequitParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmragequitparams_free(ptr >>> 0, 1));
const WasmRagequitProofResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmragequitproofresult_free(ptr >>> 0, 1));
const WasmRolloverParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmrolloverparams_free(ptr >>> 0, 1));
const WasmRolloverProofResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmrolloverproofresult_free(ptr >>> 0, 1));
const WasmStarkSignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmstarksignature_free(ptr >>> 0, 1));
const WasmTransferParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmtransferparams_free(ptr >>> 0, 1));
const WasmTransferProofResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmtransferproofresult_free(ptr >>> 0, 1));
const WasmWithdrawParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmwithdrawparams_free(ptr >>> 0, 1));
const WasmWithdrawProofResultFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmwithdrawproofresult_free(ptr >>> 0, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_externrefs.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasm;
function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('krusty_kms_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
