const core = @import("../core/root.zig");
const fr = @import("../core/field/scalar_fr.zig");
const rng = @import("rng.zig");

pub const Error = error{
    InvalidScalar,
};

pub const CURVE_ORDER = fr.CURVE_ORDER;
pub const CURVE_ORDER_INT: u256 = fr.CURVE_ORDER_INT;

pub fn reduceScalar(value: core.Felt) core.Felt {
    const reduced = fr.reduceCanonical(value.toInt());
    return core.Felt.fromInt(reduced) catch unreachable;
}

pub fn scalarAdd(a: core.Felt, b: core.Felt) core.Felt {
    const out = fr.addCanonical(a.toInt(), b.toInt());
    return core.Felt.fromInt(out) catch unreachable;
}

pub fn scalarSub(a: core.Felt, b: core.Felt) core.Felt {
    const out = fr.subCanonical(a.toInt(), b.toInt());
    return core.Felt.fromInt(out) catch unreachable;
}

pub fn scalarMul(a: core.Felt, b: core.Felt) core.Felt {
    const out = fr.mulCanonical(a.toInt(), b.toInt());
    return core.Felt.fromInt(out) catch unreachable;
}

pub fn randomScalar() core.Felt {
    var bytes: [32]u8 = undefined;
    rng.fillBytes(&bytes);
    // Match Rust she-core random::random_felt semantics:
    // sample 32 bytes and interpret through Felt parsing (field reduction).
    return core.Felt.fromBytesBeUnchecked(bytes);
}
