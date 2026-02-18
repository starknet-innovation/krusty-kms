const std = @import("std");
const core = @import("../core/root.zig");

pub const Error = error{
    InvalidInput,
    InvalidLength,
    PointAtInfinity,
    OutOfMemory,
    CryptoFailure,
};

pub const ElGamalCiphertext = struct {
    l: core.ProjectivePoint,
    r: core.ProjectivePoint,
};

pub const PoeProof = struct {
    a: core.ProjectivePoint,
    s: core.Felt,
    c: core.Felt,
};

pub const Poe2Proof = struct {
    a: core.ProjectivePoint,
    s1: core.Felt,
    s2: core.Felt,
    c: core.Felt,
};

pub const ElGamalProof = struct {
    al: core.ProjectivePoint,
    ar: core.ProjectivePoint,
    sb: core.Felt,
    sr: core.Felt,
    c: core.Felt,
};

pub const ProofOfBit = struct {
    a0: core.ProjectivePoint,
    a1: core.ProjectivePoint,
    c0: core.Felt,
    s0: core.Felt,
    s1: core.Felt,
};

pub const RangeProof = struct {
    commitments: []core.ProjectivePoint,
    proofs: []ProofOfBit,

    pub fn deinit(self: *RangeProof, allocator: std.mem.Allocator) void {
        allocator.free(self.commitments);
        allocator.free(self.proofs);
        self.* = .{
            .commitments = &.{},
            .proofs = &.{},
        };
    }
};

pub const AuditProof = struct {
    ax: core.ProjectivePoint,
    al0: core.ProjectivePoint,
    al1: core.ProjectivePoint,
    ar1: core.ProjectivePoint,
    sx: core.Felt,
    sb: core.Felt,
    sr: core.Felt,
    c: core.Felt,
};

