const U256 = @import("../u256.zig").U256;

pub const MODULUS = U256.fromHex(
    "0x0800000000000011000000000000000000000000000000000000000000000001",
) catch unreachable;
pub const MODULUS_INT: u256 = MODULUS.toInt();

const MOD_LIMBS = [4]u64{
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000000,
    0x0800000000000011,
};
const N0_INV: u64 = 0xffffffffffffffff;
const R2_LIMBS = [4]u64{
    0xfffffd737e000401,
    0x00000001330fffff,
    0xffffffffff6f8000,
    0x07ffd4ab5e008810,
};

pub fn addCanonical(a: u256, b: u256) u256 {
    var sum, const carry = @addWithOverflow(a, b);
    if (carry != 0 or sum >= MODULUS_INT) sum -= MODULUS_INT;
    return sum;
}

pub fn subCanonical(a: u256, b: u256) u256 {
    if (a >= b) return a - b;
    return (a + MODULUS_INT) - b;
}

pub fn mulCanonical(a: u256, b: u256) u256 {
    const a_limbs = u256ToLimbs(a);
    const b_limbs = u256ToLimbs(b);
    const prod_r_inv = montMul(a_limbs, b_limbs);
    const prod = montMul(prod_r_inv, R2_LIMBS);
    return limbsToU256(prod);
}

pub fn squareCanonical(a: u256) u256 {
    return mulCanonical(a, a);
}

fn montMul(a: [4]u64, b: [4]u64) [4]u64 {
    var t = [_]u64{0} ** 9;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var carry: u128 = 0;
        var j: usize = 0;
        while (j < 4) : (j += 1) {
            const idx = i + j;
            const acc: u128 = @as(u128, t[idx]) + (@as(u128, a[j]) * @as(u128, b[i])) + carry;
            t[idx] = @truncate(acc);
            carry = acc >> 64;
        }

        var k = i + 4;
        var c = carry;
        while (c != 0) : (k += 1) {
            const acc: u128 = @as(u128, t[k]) + c;
            t[k] = @truncate(acc);
            c = acc >> 64;
        }

        const m: u64 = t[i] *% N0_INV;
        carry = 0;
        j = 0;
        while (j < 4) : (j += 1) {
            const idx = i + j;
            const acc: u128 = @as(u128, t[idx]) + (@as(u128, m) * @as(u128, MOD_LIMBS[j])) + carry;
            t[idx] = @truncate(acc);
            carry = acc >> 64;
        }

        k = i + 4;
        c = carry;
        while (c != 0) : (k += 1) {
            const acc: u128 = @as(u128, t[k]) + c;
            t[k] = @truncate(acc);
            c = acc >> 64;
        }
    }

    var out = [4]u64{ t[4], t[5], t[6], t[7] };
    if (t[8] != 0 or geq(out, MOD_LIMBS)) {
        out = subNoBorrow(out, MOD_LIMBS);
        if (geq(out, MOD_LIMBS)) {
            out = subNoBorrow(out, MOD_LIMBS);
        }
    }
    return out;
}

fn u256ToLimbs(v: u256) [4]u64 {
    return .{
        @truncate(v),
        @truncate(v >> 64),
        @truncate(v >> 128),
        @truncate(v >> 192),
    };
}

fn limbsToU256(limbs: [4]u64) u256 {
    return (@as(u256, limbs[0])) |
        (@as(u256, limbs[1]) << 64) |
        (@as(u256, limbs[2]) << 128) |
        (@as(u256, limbs[3]) << 192);
}

fn geq(a: [4]u64, b: [4]u64) bool {
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        if (a[i] > b[i]) return true;
        if (a[i] < b[i]) return false;
    }
    return true;
}

fn subNoBorrow(a: [4]u64, b: [4]u64) [4]u64 {
    var out = [_]u64{0} ** 4;
    var borrow: u1 = 0;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const t1, const b1 = @subWithOverflow(a[i], b[i]);
        const t2, const b2 = @subWithOverflow(t1, borrow);
        out[i] = t2;
        borrow = @intCast(@as(u2, b1) + @as(u2, b2));
    }
    return out;
}
