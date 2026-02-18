const core = @import("../core/root.zig");
const she = @import("../she/root.zig");

pub const CipherBalance = struct {
    l: core.ProjectivePoint,
    r: core.ProjectivePoint,
};

pub const AccountState = struct {
    balance: CipherBalance,
    pending: CipherBalance,
    nonce: core.Felt,
};

pub const DecryptedAccountState = struct {
    balance: u128,
    pending: u128,
    nonce: core.Felt,
};

pub const Error = error{
    InvalidInput,
    BalanceNotFound,
};

pub const DEFAULT_MAX_SEARCH: u128 = 1_000_000_000_000;

pub fn decryptCipherBalance(
    private_key: core.Felt,
    cipher: CipherBalance,
    max_search: u128,
) Error!u128 {
    const r_x = she.curve.mul(private_key, cipher.r);
    const g_m = subtractPoints(cipher.l, r_x);
    return discreteLogBruteForce(g_m, max_search);
}

fn subtractPoints(a: core.ProjectivePoint, b: core.ProjectivePoint) core.ProjectivePoint {
    return she.curve.add(a, she.curve.neg(b));
}

fn discreteLogBruteForce(g_m: core.ProjectivePoint, max_search: u128) Error!u128 {
    if (she.curve.isInfinity(g_m)) return 0;

    const generator = she.curve.GENERATOR;
    var current = generator;
    var i: u128 = 1;
    while (i <= max_search) : (i += 1) {
        if (she.curve.pointEq(current, g_m)) return i;
        current = she.curve.add(current, generator);
    }

    return Error.BalanceNotFound;
}

