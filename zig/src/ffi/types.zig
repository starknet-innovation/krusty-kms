const core = @import("../core/root.zig");
const felt_mod = @import("../core/felt.zig");

pub const KmsFelt = extern struct {
    bytes: [32]u8,
};

pub const KmsProjectivePoint = extern struct {
    x: KmsFelt,
    y: KmsFelt,
    z: KmsFelt,
};

pub const KmsAffinePoint = extern struct {
    x: KmsFelt,
    y: KmsFelt,
};

pub const KmsTongoKeyPair = extern struct {
    private_key: KmsFelt,
    public_key: KmsProjectivePoint,
};

pub const KmsNostrKeyPair = extern struct {
    private_key: [32]u8,
    public_key_xonly: [32]u8,
};

pub fn toFelt(v: KmsFelt) core.Felt {
    return core.Felt.fromBytesBe(v.bytes) catch core.Felt.ZERO;
}

pub fn toFeltResult(v: KmsFelt) felt_mod.Error!core.Felt {
    return core.Felt.fromBytesBe(v.bytes);
}

pub fn fromFelt(v: core.Felt) KmsFelt {
    return .{ .bytes = v.toBytesBe() };
}

pub fn toProjective(v: KmsProjectivePoint) core.ProjectivePoint {
    return core.ProjectivePoint.newUnchecked(
        toFelt(v.x),
        toFelt(v.y),
        toFelt(v.z),
    );
}

pub fn fromProjective(v: core.ProjectivePoint) KmsProjectivePoint {
    return .{
        .x = fromFelt(v.x),
        .y = fromFelt(v.y),
        .z = fromFelt(v.z),
    };
}

pub fn toAffine(v: KmsAffinePoint) core.AffinePoint {
    return core.AffinePoint.new(toFelt(v.x), toFelt(v.y));
}

pub fn fromAffine(v: core.AffinePoint) KmsAffinePoint {
    return .{
        .x = fromFelt(v.x),
        .y = fromFelt(v.y),
    };
}
