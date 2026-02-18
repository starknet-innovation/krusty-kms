const core = @import("../core/root.zig");
const constants = @import("generated/poseidon_constants.zig");

pub const Error = error{
    CryptoFailure,
};

pub fn hash2(a: core.Felt, b: core.Felt) Error!core.Felt {
    var state = [_]core.Felt{
        a,
        b,
        core.Felt.TWO,
    };
    hadesPermutation(&state);
    return state[0];
}

pub fn hashMany(values: []const core.Felt) Error!core.Felt {
    var state = [_]core.Felt{
        core.Felt.ZERO,
        core.Felt.ZERO,
        core.Felt.ZERO,
    };

    var i: usize = 0;
    while (i < values.len) : (i += 2) {
        const v0 = values[i];
        const v1 = if (i + 1 < values.len) values[i + 1] else core.Felt.ONE;

        state[0] = state[0].add(v0);
        state[1] = state[1].add(v1);
        hadesPermutation(&state);
    }

    if (values.len % 2 == 0) {
        // Poseidon hash_many uses domain separator 1 plus zero padding.
        state[0] = state[0].add(core.Felt.ONE);
        state[1] = state[1].add(core.Felt.ZERO);
        hadesPermutation(&state);
    }

    return state[0];
}

fn hadesPermutation(state: *[3]core.Felt) void {
    var index: usize = 0;

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        fullRound(state, index);
        index += 3;
    }

    i = 0;
    while (i < 83) : (i += 1) {
        partialRound(state, index);
        index += 1;
    }

    i = 0;
    while (i < 4) : (i += 1) {
        fullRound(state, index);
        index += 3;
    }
}

fn fullRound(state: *[3]core.Felt, index: usize) void {
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        state[i] = state[i].add(constants.ROUND_CONSTANTS[index + i]);
        state[i] = state[i].square().mul(state[i]);
    }
    mix(state);
}

fn partialRound(state: *[3]core.Felt, index: usize) void {
    state[2] = state[2].add(constants.ROUND_CONSTANTS[index]);
    state[2] = state[2].square().mul(state[2]);
    mix(state);
}

fn mix(state: *[3]core.Felt) void {
    const t = state[0].add(state[1]).add(state[2]);
    state[0] = t.add(state[0].add(state[0]));
    state[1] = t.sub(state[1].add(state[1]));
    state[2] = t.sub(state[2].add(state[2]).add(state[2]));
}
