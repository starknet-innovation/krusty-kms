const Felt = @import("felt.zig").Felt;

pub const Error = error{
    PointAtInfinity,
    InvalidPoint,
    DivisionByZero,
};

// Stark curve equation: y^2 = x^3 + x + b
pub const CURVE_B = Felt.fromHex(
    "0x06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89",
) catch unreachable;

pub const GENERATOR_X = Felt.fromHex(
    "0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
) catch unreachable;
pub const GENERATOR_Y = Felt.fromHex(
    "0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f",
) catch unreachable;

const TWO = Felt.TWO;
const THREE = Felt.fromU64(3);
const FOUR = Felt.fromU64(4);
const EIGHT = Felt.fromU64(8);

pub const AffinePoint = struct {
    x: Felt,
    y: Felt,

    pub fn new(x: Felt, y: Felt) AffinePoint {
        return .{
            .x = x,
            .y = y,
        };
    }

    pub fn isOnCurve(self: AffinePoint) bool {
        const lhs = self.y.square();
        const rhs = self.x.square().mul(self.x).add(self.x).add(CURVE_B);
        return Felt.eql(lhs, rhs);
    }

    pub fn neg(self: AffinePoint) AffinePoint {
        return .{
            .x = self.x,
            .y = self.y.neg(),
        };
    }
};

pub const ProjectivePoint = struct {
    x: Felt,
    y: Felt,
    z: Felt,

    pub fn identity() ProjectivePoint {
        return .{
            .x = Felt.ZERO,
            .y = Felt.ONE,
            .z = Felt.ZERO,
        };
    }

    pub fn generator() ProjectivePoint {
        return fromAffine(GENERATOR_X, GENERATOR_Y);
    }

    pub fn fromAffine(x: Felt, y: Felt) ProjectivePoint {
        return .{
            .x = x,
            .y = y,
            .z = Felt.ONE,
        };
    }

    pub fn newUnchecked(x: Felt, y: Felt, z: Felt) ProjectivePoint {
        return .{
            .x = x,
            .y = y,
            .z = z,
        };
    }

    pub fn isIdentity(self: ProjectivePoint) bool {
        return self.z.isZero();
    }

    pub fn toAffine(self: ProjectivePoint) ?AffinePoint {
        if (self.isIdentity()) return null;

        if (Felt.eql(self.z, Felt.ONE)) {
            return AffinePoint.new(self.x, self.y);
        }

        const z_inv = self.z.inverse() catch return null;
        const z2 = z_inv.square();
        const z3 = z2.mul(z_inv);
        return AffinePoint.new(self.x.mul(z2), self.y.mul(z3));
    }

    pub fn toAffineResult(self: ProjectivePoint) Error!AffinePoint {
        const affine = self.toAffine() orelse return Error.PointAtInfinity;
        return affine;
    }

    pub fn add(self: ProjectivePoint, other: ProjectivePoint) ProjectivePoint {
        return addJacobian(self, other);
    }

    pub fn addMixed(self: ProjectivePoint, other: AffinePoint) ProjectivePoint {
        return addMixedJacobian(self, other);
    }

    pub fn dbl(self: ProjectivePoint) ProjectivePoint {
        return doubleJacobian(self);
    }

    // Backward-compatible default multiply path (variable-time, optimized for throughput).
    pub fn scalarMul(base: ProjectivePoint, scalar: Felt) ProjectivePoint {
        if (isGeneratorPoint(base)) {
            return scalarMulGeneratorPublicVt(scalar);
        }
        return scalarMulPublicVt(base, scalar);
    }

    // Secret-scalar path for constant-time usage.
    pub fn scalarMulSecretCt(base: ProjectivePoint, scalar: Felt) ProjectivePoint {
        if (scalar.isZero()) return identity();

        var table: [16]ProjectivePoint = undefined;
        table[0] = identity();
        table[1] = base;
        var i: usize = 2;
        while (i < table.len) : (i += 1) {
            table[i] = table[i - 1].add(base);
        }

        const bytes = scalar.toBytesBe();
        var result = identity();
        for (bytes) |byte| {
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            const hi: u8 = byte >> 4;
            result = result.add(ctSelectPoint(table, hi));

            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            const lo: u8 = byte & 0x0f;
            result = result.add(ctSelectPoint(table, lo));
        }

        return result;
    }

    // Public-scalar path (variable-time fixed-window).
    pub fn scalarMulPublicVt(base: ProjectivePoint, scalar: Felt) ProjectivePoint {
        if (isGeneratorPoint(base)) {
            return scalarMulGeneratorPublicVt(scalar);
        }
        if (scalar.isZero()) return identity();

        if (scalarPowerOfTwoShift(scalar)) |shift| {
            return mulByPow2(base, shift);
        }

        // Variable-time wNAF (w=5) keeps doublings fixed and reduces additions.
        const w = 5;
        const table_len = 1 << (w - 2); // odd multiples: 1P..15P

        var odd_table: [table_len]ProjectivePoint = undefined;
        odd_table[0] = base; // 1P
        const two_p = base.dbl();
        var t: usize = 1;
        while (t < odd_table.len) : (t += 1) {
            odd_table[t] = odd_table[t - 1].add(two_p);
        }

        var k = scalar.toInt();
        var digits: [260]i8 = undefined;
        var dlen: usize = 0;

        while (k != 0) {
            if ((k & 1) == 1) {
                const rem: u8 = @truncate(k & ((1 << w) - 1));
                var digit: i8 = @intCast(rem);
                if (digit > (1 << (w - 1))) {
                    digit -= (1 << w);
                }
                digits[dlen] = digit;
                if (digit > 0) {
                    k -%= @as(u256, @intCast(digit));
                } else {
                    k +%= @as(u256, @intCast(-digit));
                }
            } else {
                digits[dlen] = 0;
            }
            dlen += 1;
            k >>= 1;
        }

        var result = identity();
        var i: usize = dlen;
        while (i > 0) {
            i -= 1;
            result = result.dbl();
            const digit = digits[i];
            if (digit > 0) {
                const idx: usize = @intCast((@as(u8, @intCast(digit)) - 1) >> 1);
                result = result.add(odd_table[idx]);
            } else if (digit < 0) {
                const idx: usize = @intCast((@as(u8, @intCast(-digit)) - 1) >> 1);
                result = result.add(negPoint(odd_table[idx]));
            }
        }
        return result;
    }

    pub fn scalarMulGeneratorPublicVt(scalar: Felt) ProjectivePoint {
        if (scalar.isZero()) return identity();

        const table = getGeneratorPrecompute();
        const bytes = scalar.toBytesBe();
        var result = identity();

        for (bytes) |byte| {
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();
            result = result.dbl();

            if (byte != 0) {
                result = result.add(table[@intCast(byte)]);
            }
        }
        return result;
    }
};

var generator_precompute_ready = false;
var generator_precompute: [256]ProjectivePoint = undefined;

fn doubleJacobian(p: ProjectivePoint) ProjectivePoint {
    if (p.isIdentity()) return p;
    if (p.y.isZero()) return ProjectivePoint.identity();

    const xx = p.x.square();
    const yy = p.y.square();
    const yyyy = yy.square();
    const zz = p.z.square();
    const zzzz = zz.square();

    const s = p.x.mul(yy).mul(FOUR);
    const m = xx.mul(THREE).add(zzzz);

    const x3 = m.square().sub(s.mul(TWO));
    const y3 = m.mul(s.sub(x3)).sub(yyyy.mul(EIGHT));
    const z3 = p.y.mul(p.z).mul(TWO);

    return ProjectivePoint.newUnchecked(x3, y3, z3);
}

fn addJacobian(p: ProjectivePoint, q: ProjectivePoint) ProjectivePoint {
    if (p.isIdentity()) return q;
    if (q.isIdentity()) return p;

    const z1z1 = p.z.square();
    const z2z2 = q.z.square();

    const u1v = p.x.mul(z2z2);
    const u2v = q.x.mul(z1z1);

    const s1 = p.y.mul(q.z).mul(z2z2);
    const s2 = q.y.mul(p.z).mul(z1z1);

    if (Felt.eql(u1v, u2v)) {
        if (!Felt.eql(s1, s2)) return ProjectivePoint.identity();
        return doubleJacobian(p);
    }

    const h = u2v.sub(u1v);
    const i = h.mul(TWO).square();
    const j = h.mul(i);
    const r = s2.sub(s1).mul(TWO);
    const v = u1v.mul(i);

    const x3 = r.square().sub(j).sub(v.mul(TWO));
    const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).mul(TWO));
    const z3 = p.z.add(q.z).square().sub(z1z1).sub(z2z2).mul(h);

    return ProjectivePoint.newUnchecked(x3, y3, z3);
}

fn addMixedJacobian(p: ProjectivePoint, q: AffinePoint) ProjectivePoint {
    if (p.isIdentity()) return ProjectivePoint.fromAffine(q.x, q.y);

    const z1z1 = p.z.square();
    const u2v = q.x.mul(z1z1);
    const s2 = q.y.mul(p.z).mul(z1z1);

    if (Felt.eql(p.x, u2v)) {
        if (!Felt.eql(p.y, s2)) return ProjectivePoint.identity();
        return doubleJacobian(p);
    }

    const h = u2v.sub(p.x);
    const hh = h.square();
    const i = hh.mul(FOUR);
    const j = h.mul(i);
    const r = s2.sub(p.y).mul(TWO);
    const v = p.x.mul(i);

    const x3 = r.square().sub(j).sub(v.mul(TWO));
    const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).mul(TWO));
    const z3 = p.z.add(h).square().sub(z1z1).sub(hh);

    return ProjectivePoint.newUnchecked(x3, y3, z3);
}

fn ctSelectPoint(table: [16]ProjectivePoint, index: u8) ProjectivePoint {
    var x: u256 = 0;
    var y: u256 = 0;
    var z: u256 = 0;

    var i: u8 = 0;
    while (i < 16) : (i += 1) {
        const mask = (0 -% @as(u256, @intFromBool(i == index)));
        x = (x & ~mask) | (table[i].x.toInt() & mask);
        y = (y & ~mask) | (table[i].y.toInt() & mask);
        z = (z & ~mask) | (table[i].z.toInt() & mask);
    }

    return ProjectivePoint.newUnchecked(
        Felt.fromInt(x) catch unreachable,
        Felt.fromInt(y) catch unreachable,
        Felt.fromInt(z) catch unreachable,
    );
}

fn negPoint(p: ProjectivePoint) ProjectivePoint {
    if (p.isIdentity()) return p;
    return ProjectivePoint.newUnchecked(p.x, p.y.neg(), p.z);
}

fn scalarPowerOfTwoShift(scalar: Felt) ?u8 {
    const v = scalar.toInt();
    if (v == 0) return null;
    if ((v & (v - 1)) != 0) return null;
    return @intCast(@ctz(v));
}

fn mulByPow2(base: ProjectivePoint, shift: u8) ProjectivePoint {
    if (shift == 0) return base;
    var out = base;
    var i: u8 = 0;
    while (i < shift) : (i += 1) {
        out = out.dbl();
    }
    return out;
}

fn isGeneratorPoint(p: ProjectivePoint) bool {
    return Felt.eql(p.z, Felt.ONE) and Felt.eql(p.x, GENERATOR_X) and Felt.eql(p.y, GENERATOR_Y);
}

fn getGeneratorPrecompute() *const [256]ProjectivePoint {
    if (!generator_precompute_ready) {
        const g = ProjectivePoint.generator();
        generator_precompute[0] = ProjectivePoint.identity();
        generator_precompute[1] = g;
        var i: usize = 2;
        while (i < generator_precompute.len) : (i += 1) {
            generator_precompute[i] = generator_precompute[i - 1].add(g);
        }
        generator_precompute_ready = true;
    }
    return &generator_precompute;
}

pub fn computePublicKey(private_key: Felt) Error!ProjectivePoint {
    if (private_key.isZero()) return Error.InvalidPoint;
    return ProjectivePoint.scalarMulSecretCt(ProjectivePoint.generator(), private_key);
}
