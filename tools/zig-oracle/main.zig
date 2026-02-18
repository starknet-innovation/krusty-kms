const std = @import("std");
const kms_zig = @import("kms_zig");

const VERSION = "zig-oracle/0.2.0";

const HandlerResult = struct {
    output: std.json.Value,
    bytes: []u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdin = std.fs.File.stdin();
    const payload = try stdin.deprecatedReader().readAllAlloc(allocator, 2 * 1024 * 1024);
    defer allocator.free(payload);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch {
        try writeError(allocator, "invalid request json");
        return;
    };
    defer parsed.deinit();

    const req = parsed.value;
    if (req != .object) {
        try writeError(allocator, "request must be object");
        return;
    }

    const op = getString(req.object, "op") catch {
        try writeError(allocator, "missing op");
        return;
    };

    const inputs = req.object.get("inputs") orelse std.json.Value{ .object = std.json.ObjectMap.init(allocator) };

    var rng_enabled = false;
    if (req.object.get("rng")) |rng_val| {
        if (rng_val == .object) {
            const mode = rng_val.object.get("mode");
            if (mode) |m| {
                if (m == .string and std.mem.eql(u8, m.string, "deterministic")) {
                    const seed_hex = getString(rng_val.object, "seed_hex") catch {
                        try writeError(allocator, "rng.seed_hex missing");
                        return;
                    };
                    const stream = getString(rng_val.object, "stream") catch {
                        try writeError(allocator, "rng.stream missing");
                        return;
                    };
                    const seed = parseSeed32(seed_hex) catch {
                        try writeError(allocator, "rng.seed_hex must be 32-byte hex");
                        return;
                    };
                    kms_zig.she.rng.setDeterministic(seed, stream) catch {
                        try writeError(allocator, "failed to set deterministic rng");
                        return;
                    };
                    rng_enabled = true;
                }
            }
        }
    }
    defer if (rng_enabled) kms_zig.she.rng.clearDeterministic();

    const handled = handleOp(allocator, op, inputs) catch |err| {
        const msg = @errorName(err);
        try writeError(allocator, msg);
        return;
    };

    try writeSuccess(allocator, handled.output, handled.bytes);
}

fn handleOp(allocator: std.mem.Allocator, op: []const u8, inputs: std.json.Value) !HandlerResult {
    if (std.mem.eql(u8, op, "kms.coin_types")) {
        var out = std.json.ObjectMap.init(allocator);
        try out.put("tongo", .{ .integer = 5454 });
        try out.put("starknet", .{ .integer = 9004 });
        try out.put("tongo_view", .{ .integer = 5353 });
        try out.put("nostr", .{ .integer = 1237 });
        return .{ .output = .{ .object = out }, .bytes = &.{} };
    }

    if (std.mem.eql(u8, op, "kms.felt_roundtrip_hex")) {
        const hex = try getStringFromInputs(inputs, "hex");
        const felt = try kms_zig.core.Felt.fromHex(hex);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("hex", .{ .string = try feltHex(allocator, felt) });
        const bytes = try dupBytes(allocator, &felt.toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.pedersen_hash")) {
        const left = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "left"));
        const right = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "right"));
        const hash = try kms_zig.crypto.pedersen.hash(left, right);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("hash", .{ .string = try feltHex(allocator, hash) });
        const bytes = try dupBytes(allocator, &hash.toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.poseidon_hash_many") or std.mem.eql(u8, op, "she.poseidon_hash_many")) {
        const values = try feltArrayFromInputs(allocator, inputs, "values");
        const hash = try kms_zig.crypto.poseidon.hashMany(values);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("hash", .{ .string = try feltHex(allocator, hash) });
        const bytes = try dupBytes(allocator, &hash.toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.validate_mnemonic")) {
        const phrase = try getStringFromInputs(inputs, "phrase");
        const ok = blk: {
            kms_zig.kms.mnemonic.validateMnemonic(phrase) catch break :blk false;
            break :blk true;
        };
        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = ok });
        const bytes = try allocator.alloc(u8, 1);
        bytes[0] = if (ok) 1 else 0;
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.mnemonic_to_seed")) {
        const phrase = try getStringFromInputs(inputs, "phrase");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");
        const seed = try kms_zig.kms.mnemonic.mnemonicToSeed(phrase, passphrase);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("seed_hex", .{ .string = try hexEncodeAlloc(allocator, &seed) });
        const bytes = try dupBytes(allocator, &seed);
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.derive_private_key_with_coin_type")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const coin_type = try getU32FromInputs(inputs, "coin_type");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");
        const private_key = try kms_zig.kms.derivation.derivePrivateKeyWithCoinType(
            mnemonic,
            index,
            account_index,
            coin_type,
            passphrase,
        );
        var out = std.json.ObjectMap.init(allocator);
        try out.put("private_key", .{ .string = try feltHex(allocator, private_key) });
        const bytes = try dupBytes(allocator, &private_key.toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.derive_keypair_with_coin_type") or std.mem.eql(u8, op, "kms.derive_view_keypair")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");

        const keypair = if (std.mem.eql(u8, op, "kms.derive_view_keypair"))
            try kms_zig.kms.derivation.deriveViewKeypair(mnemonic, index, account_index, passphrase)
        else blk: {
            const coin_type = try getU32FromInputs(inputs, "coin_type");
            break :blk try kms_zig.kms.derivation.deriveKeypairWithCoinType(
                mnemonic,
                index,
                account_index,
                coin_type,
                passphrase,
            );
        };

        const point_obj = try pointJson(allocator, keypair.public_key);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("private_key", .{ .string = try feltHex(allocator, keypair.private_key) });
        try out.put("public_key", .{ .object = point_obj });

        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, &keypair.private_key.toBytesBe());
        const pbytes = try projectiveBytes(allocator, keypair.public_key);
        try bytes.appendSlice(allocator, pbytes);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "kms.derive_view_private_key")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");
        const private_key = try kms_zig.kms.derivation.deriveViewPrivateKey(
            mnemonic,
            index,
            account_index,
            passphrase,
        );
        var out = std.json.ObjectMap.init(allocator);
        try out.put("private_key", .{ .string = try feltHex(allocator, private_key) });
        const bytes = try dupBytes(allocator, &private_key.toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "kms.derive_nostr_private_key")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");
        const key = try kms_zig.kms.derivation.deriveNostrPrivateKey(mnemonic, index, account_index, passphrase);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("private_key_hex", .{ .string = try hexEncodeAlloc(allocator, &key) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, &key) };
    }

    if (std.mem.eql(u8, op, "kms.derive_nostr_keypair")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const passphrase = getStringFromInputsDefault(inputs, "passphrase", "");
        const kp = try kms_zig.kms.derivation.deriveNostrKeypair(mnemonic, index, account_index, passphrase);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("private_key_hex", .{ .string = try hexEncodeAlloc(allocator, &kp.private_key) });
        try out.put("public_key_xonly_hex", .{ .string = try hexEncodeAlloc(allocator, &kp.public_key_xonly) });
        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, &kp.private_key);
        try bytes.appendSlice(allocator, &kp.public_key_xonly);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "kms.calculate_contract_address")) {
        const salt = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "salt"));
        const class_hash = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "class_hash"));
        const deployer = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "deployer"));
        const calldata = try feltArrayFromInputs(allocator, inputs, "constructor_calldata");
        const address = try kms_zig.kms.account.calculateContractAddress(salt, class_hash, calldata, deployer);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("address", .{ .string = try feltHex(allocator, address) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, &address.toBytesBe()) };
    }

    if (std.mem.eql(u8, op, "kms.derive_oz_account_address")) {
        const public_x = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "public_key_x"));
        const class_hash = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "class_hash"));
        const salt_hex = maybeStringFromInputs(inputs, "salt");
        const salt = if (salt_hex) |s| try kms_zig.core.Felt.fromHex(s) else kms_zig.core.Felt.ZERO;
        const address = try kms_zig.kms.account.deriveOzAccountAddress(public_x, class_hash, salt);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("address", .{ .string = try feltHex(allocator, address) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, &address.toBytesBe()) };
    }

    if (std.mem.eql(u8, op, "she.scalar_add") or std.mem.eql(u8, op, "she.scalar_mul") or std.mem.eql(u8, op, "she.reduce_scalar")) {
        const a = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "a"));
        const result = if (std.mem.eql(u8, op, "she.reduce_scalar"))
            kms_zig.she.scalar.reduceScalar(a)
        else blk: {
            const b = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "b"));
            if (std.mem.eql(u8, op, "she.scalar_add")) {
                break :blk kms_zig.she.scalar.scalarAdd(a, b);
            }
            break :blk kms_zig.she.scalar.scalarMul(a, b);
        };
        var out = std.json.ObjectMap.init(allocator);
        try out.put("result", .{ .string = try feltHex(allocator, result) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, &result.toBytesBe()) };
    }

    if (std.mem.eql(u8, op, "she.curve_mul_generator")) {
        const scalar = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "scalar"));
        const point = kms_zig.she.curve.mulGenerator(scalar);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("point", .{ .object = try pointJson(allocator, point) });
        return .{ .output = .{ .object = out }, .bytes = try projectiveBytes(allocator, point) };
    }

    if (std.mem.eql(u8, op, "she.poe_prove_verify")) {
        const x = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "x"));
        const prefix = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "prefix"));
        const res = try kms_zig.she.poe.prove(allocator, x, prefix);
        const valid = try kms_zig.she.poe.verify(allocator, res.y, res.proof, prefix);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = valid });
        try out.put("y", .{ .object = try pointJson(allocator, res.y) });
        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, res.y));
        try bytes.append(allocator, if (valid) 1 else 0);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "she.poe2_prove_verify")) {
        const x1 = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "x1"));
        const x2 = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "x2"));
        const prefix = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "prefix"));
        const res = try kms_zig.she.poe2.prove(x1, x2, kms_zig.she.curve.GENERATOR, kms_zig.she.curve.GENERATOR_H, prefix);
        const valid = try kms_zig.she.poe2.verify(res.y, kms_zig.she.curve.GENERATOR, kms_zig.she.curve.GENERATOR_H, res.proof, prefix);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = valid });
        try out.put("y", .{ .object = try pointJson(allocator, res.y) });
        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, res.y));
        try bytes.append(allocator, if (valid) 1 else 0);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "she.elgamal_encrypt_verify_decrypt")) {
        const message = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "message"));
        const sk = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "private_key"));
        const randomness = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "randomness"));
        const prefix = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "prefix"));
        const pk = kms_zig.she.curve.mul(sk, kms_zig.she.curve.GENERATOR);
        const enc = try kms_zig.she.elgamal.encrypt(message, pk, randomness, prefix);
        const valid = try kms_zig.she.elgamal.verify(enc.l, enc.r, pk, enc.proof, prefix);
        const dec = try kms_zig.she.elgamal.decrypt(.{ .l = enc.l, .r = enc.r }, sk);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = valid });
        try out.put("l", .{ .object = try pointJson(allocator, enc.l) });
        try out.put("r", .{ .object = try pointJson(allocator, enc.r) });
        try out.put("decrypted", .{ .object = try pointJson(allocator, dec) });

        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, enc.l));
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, enc.r));
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, dec));
        try bytes.append(allocator, if (valid) 1 else 0);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "she.bit_prove_verify")) {
        const bit = @as(u8, @intCast(try getU32FromInputs(inputs, "bit")));
        const random = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "random"));
        const prefix = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "prefix"));
        const prove_res = try kms_zig.she.bit.prove(
            allocator,
            bit,
            random,
            kms_zig.she.curve.GENERATOR,
            kms_zig.she.curve.GENERATOR_H,
            prefix,
        );
        const valid = try kms_zig.she.bit.verify(
            allocator,
            prove_res.v,
            kms_zig.she.curve.GENERATOR,
            kms_zig.she.curve.GENERATOR_H,
            prove_res.proof,
            prefix,
        );

        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = valid });
        try out.put("v", .{ .object = try pointJson(allocator, prove_res.v) });

        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, prove_res.v));
        try bytes.append(allocator, if (valid) 1 else 0);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "she.range_prove_verify")) {
        const value = try getU128FromInputs(inputs, "value");
        const bit_size = @as(usize, @intCast(try getU32FromInputs(inputs, "bit_size")));
        const prefix = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "prefix"));

        var prove_res = try kms_zig.she.range.prove(allocator, value, bit_size, kms_zig.she.curve.GENERATOR, kms_zig.she.curve.GENERATOR_H, prefix);
        defer prove_res.range.deinit(allocator);
        const v = try kms_zig.she.range.verify(allocator, prove_res.range, bit_size, kms_zig.she.curve.GENERATOR, kms_zig.she.curve.GENERATOR_H, prefix);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("commitments", .{ .integer = @intCast(prove_res.range.commitments.len) });
        try out.put("proofs", .{ .integer = @intCast(prove_res.range.proofs.len) });
        try out.put("v", .{ .object = try pointJson(allocator, v) });

        var bytes: std.ArrayList(u8) = .empty;
        var lenb: [4]u8 = undefined;
        std.mem.writeInt(u32, &lenb, @intCast(prove_res.range.commitments.len), .big);
        try bytes.appendSlice(allocator, &lenb);
        std.mem.writeInt(u32, &lenb, @intCast(prove_res.range.proofs.len), .big);
        try bytes.appendSlice(allocator, &lenb);
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, v));
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "she.audit_prove_verify")) {
        const private_key = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "private_key"));
        const balance = try getU128FromInputs(inputs, "balance");
        const cipher_random = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "cipher_random"));
        const auditor_sk = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "auditor_private_key"));

        const g = kms_zig.she.curve.GENERATOR;
        const user_pk = kms_zig.she.curve.mul(private_key, g);
        const auditor_pk = kms_zig.she.curve.mul(auditor_sk, g);
        const l0 = kms_zig.she.curve.add(
            kms_zig.she.curve.mul(feltFromU128(balance), g),
            kms_zig.she.curve.mul(cipher_random, user_pk),
        );
        const cipher0 = kms_zig.she.types.ElGamalCiphertext{ .l = l0, .r = kms_zig.she.curve.mul(cipher_random, g) };

        const prove_res = try kms_zig.she.audit.prove(allocator, private_key, balance, cipher0, auditor_pk);
        const valid = try kms_zig.she.audit.verify(allocator, prove_res.proof, user_pk, cipher0, prove_res.cipher1, auditor_pk);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("valid", .{ .bool = valid });
        try out.put("cipher1_l", .{ .object = try pointJson(allocator, prove_res.cipher1.l) });
        try out.put("cipher1_r", .{ .object = try pointJson(allocator, prove_res.cipher1.r) });

        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, prove_res.cipher1.l));
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, prove_res.cipher1.r));
        try bytes.append(allocator, if (valid) 1 else 0);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "tongo.audit_hint_roundtrip")) {
        const balance = try getU128FromInputs(inputs, "balance");
        const user_sk = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "user_private_key"));
        const auditor_sk = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "auditor_private_key"));

        const g = kms_zig.she.curve.GENERATOR;
        const user_pk = kms_zig.she.curve.mul(user_sk, g);
        const auditor_pk = kms_zig.she.curve.mul(auditor_sk, g);

        const hint = try kms_zig.tongo.crypto.encryptForAuditor(balance, user_sk, auditor_pk);
        const decrypted = try kms_zig.tongo.crypto.decryptAsAuditor(hint.ciphertext, hint.nonce, auditor_sk, user_pk);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("decrypted", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{decrypted}) });
        try out.put("ciphertext_hex", .{ .string = try hexEncodeAlloc(allocator, &hint.ciphertext) });
        try out.put("nonce_hex", .{ .string = try hexEncodeAlloc(allocator, &hint.nonce) });

        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, &hint.ciphertext);
        try bytes.appendSlice(allocator, &hint.nonce);
        var db: [16]u8 = undefined;
        std.mem.writeInt(u128, &db, decrypted, .big);
        try bytes.appendSlice(allocator, &db);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "tongo.account_from_mnemonic")) {
        const mnemonic = try getStringFromInputs(inputs, "mnemonic");
        const index = try getU32FromInputs(inputs, "index");
        const account_index = try getU32FromInputs(inputs, "account_index");
        const contract_address = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "contract_address"));
        const passphrase = maybeStringFromInputs(inputs, "passphrase");

        const account = try kms_zig.tongo.TongoAccount.fromMnemonic(
            mnemonic,
            index,
            account_index,
            contract_address,
            passphrase,
        );

        const owner_aff = account.keypair.public_key.toAffine() orelse return error.PointAtInfinity;
        var out = std.json.ObjectMap.init(allocator);
        try out.put("owner_x", .{ .string = try feltHex(allocator, owner_aff.x) });
        try out.put("owner_y", .{ .string = try feltHex(allocator, owner_aff.y) });
        try out.put("has_view_key", .{ .bool = account.hasViewKey() });

        if (account.view_keypair) |view_kp| {
            const view_aff = view_kp.public_key.toAffine() orelse return error.PointAtInfinity;
            try out.put("view_x", .{ .string = try feltHex(allocator, view_aff.x) });
            try out.put("view_y", .{ .string = try feltHex(allocator, view_aff.y) });
        } else {
            try out.put("view_x", .null);
            try out.put("view_y", .null);
        }

        return .{ .output = .{ .object = out }, .bytes = &.{} };
    }

    if (std.mem.eql(u8, op, "tongo.fund")) {
        var account = try reqTestAccount(inputs);
        const amount = try getU128FromInputs(inputs, "amount");
        const nonce = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "nonce"));
        const chain_id = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "chain_id"));
        const current_balance = try reqCurrentBalance(inputs, &account);

        const proof = try kms_zig.tongo.operations.fund(
            allocator,
            &account,
            .{
                .amount = amount,
                .nonce = nonce,
                .chain_id = chain_id,
                .tongo_address = account.contract_address,
                .current_balance = current_balance,
            },
        );

        const y_affine = proof.y.toAffine() orelse return error.PointAtInfinity;
        var out = std.json.ObjectMap.init(allocator);
        try out.put("amount", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{proof.amount}) });
        try out.put("y_x", .{ .string = try feltHex(allocator, y_affine.x) });
        try out.put("y_y", .{ .string = try feltHex(allocator, y_affine.y) });

        var bytes: std.ArrayList(u8) = .empty;
        var amount_be: [16]u8 = undefined;
        std.mem.writeInt(u128, &amount_be, proof.amount, .big);
        try bytes.appendSlice(allocator, &amount_be);
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, proof.y));
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "tongo.rollover")) {
        var account = try reqTestAccount(inputs);
        const nonce = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "nonce"));
        const chain_id = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "chain_id"));
        const proof = try kms_zig.tongo.operations.rollover(
            allocator,
            &account,
            .{
                .nonce = nonce,
                .chain_id = chain_id,
                .tongo_address = account.contract_address,
            },
        );

        var out = std.json.ObjectMap.init(allocator);
        try out.put("pending_amount", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{proof.pending_amount}) });
        try out.put("y", .{ .object = try pointJson(allocator, proof.y) });

        var bytes: std.ArrayList(u8) = .empty;
        var pending_be: [16]u8 = undefined;
        std.mem.writeInt(u128, &pending_be, proof.pending_amount, .big);
        try bytes.appendSlice(allocator, &pending_be);
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, proof.y));
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "tongo.transfer")) {
        var account = try reqTestAccount(inputs);
        const amount = try getU128FromInputs(inputs, "amount");
        const nonce = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "nonce"));
        const chain_id = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "chain_id"));
        const bit_size = @as(usize, @intCast(try getU64FromInputs(inputs, "bit_size")));
        const recipient_private = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "recipient_private_key"));
        const recipient_public_key = kms_zig.she.curve.mul(recipient_private, kms_zig.she.curve.GENERATOR);
        const current_balance = try reqCurrentBalance(inputs, &account);

        var proof = try kms_zig.tongo.operations.transfer(
            allocator,
            &account,
            .{
                .recipient_public_key = recipient_public_key,
                .amount = amount,
                .nonce = nonce,
                .chain_id = chain_id,
                .tongo_address = account.contract_address,
                .current_balance = current_balance,
                .bit_size = bit_size,
            },
        );
        defer proof.deinit(allocator);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("transfer_l", .{ .object = try pointJson(allocator, proof.transfer_balance_l) });
        try out.put("transfer_r", .{ .object = try pointJson(allocator, proof.transfer_balance_r) });
        try out.put("new_balance_l", .{ .object = try pointJson(allocator, proof.new_balance_cipher.l) });
        try out.put("new_balance_r", .{ .object = try pointJson(allocator, proof.new_balance_cipher.r) });
        return .{ .output = .{ .object = out }, .bytes = &.{} };
    }

    if (std.mem.eql(u8, op, "tongo.withdraw")) {
        var account = try reqTestAccount(inputs);
        const amount = try getU128FromInputs(inputs, "amount");
        const nonce = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "nonce"));
        const chain_id = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "chain_id"));
        const bit_size = @as(usize, @intCast(try getU64FromInputs(inputs, "bit_size")));
        const recipient = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "recipient"));
        const current_balance = try reqCurrentBalance(inputs, &account);

        var proof = try kms_zig.tongo.operations.withdraw(
            allocator,
            &account,
            .{
                .recipient_address = recipient,
                .amount = amount,
                .nonce = nonce,
                .chain_id = chain_id,
                .tongo_address = account.contract_address,
                .current_balance = current_balance,
                .bit_size = bit_size,
            },
        );
        defer proof.deinit(allocator);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("amount", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{proof.amount}) });
        try out.put("recipient", .{ .string = try feltHex(allocator, proof.recipient) });
        try out.put("y", .{ .object = try pointJson(allocator, proof.y) });

        var bytes: std.ArrayList(u8) = .empty;
        var amount_be: [16]u8 = undefined;
        std.mem.writeInt(u128, &amount_be, proof.amount, .big);
        try bytes.appendSlice(allocator, &amount_be);
        try bytes.appendSlice(allocator, &proof.recipient.toBytesBe());
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, proof.y));
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "tongo.ragequit")) {
        var account = try reqTestAccount(inputs);
        const nonce = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "nonce"));
        const chain_id = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "chain_id"));
        const recipient = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "recipient"));
        const current_balance = try reqCurrentBalance(inputs, &account);

        const proof = try kms_zig.tongo.operations.ragequit(
            allocator,
            &account,
            .{
                .recipient_address = recipient,
                .nonce = nonce,
                .chain_id = chain_id,
                .tongo_address = account.contract_address,
                .current_balance = current_balance,
            },
        );

        var out = std.json.ObjectMap.init(allocator);
        try out.put("amount", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{proof.amount}) });
        try out.put("recipient", .{ .string = try feltHex(allocator, proof.recipient) });
        try out.put("y", .{ .object = try pointJson(allocator, proof.y) });

        var bytes: std.ArrayList(u8) = .empty;
        var amount_be: [16]u8 = undefined;
        std.mem.writeInt(u128, &amount_be, proof.amount, .big);
        try bytes.appendSlice(allocator, &amount_be);
        try bytes.appendSlice(allocator, &proof.recipient.toBytesBe());
        try bytes.appendSlice(allocator, try projectiveBytes(allocator, proof.y));
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "nostr.derive_public_key")) {
        const secret = try getStringFromInputs(inputs, "secret_hex");
        const pk = try kms_zig.nostr.derivePublicKey(allocator, secret);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("public_key_hex", .{ .string = pk });
        const bytes = try hexDecodeAlloc(allocator, pk);
        return .{ .output = .{ .object = out }, .bytes = bytes };
    }

    if (std.mem.eql(u8, op, "nostr.encrypt_decrypt_roundtrip")) {
        const sender_sk = try getStringFromInputs(inputs, "sender_sk_hex");
        const receiver_sk = try getStringFromInputs(inputs, "receiver_sk_hex");
        const plaintext = try getStringFromInputs(inputs, "plaintext");
        const sender_pk = try kms_zig.nostr.derivePublicKey(allocator, sender_sk);
        const receiver_pk = try kms_zig.nostr.derivePublicKey(allocator, receiver_sk);
        const payload = try kms_zig.nostr.encryptMessage(allocator, sender_sk, receiver_pk, plaintext);
        const decrypted = try kms_zig.nostr.decryptMessage(allocator, receiver_sk, sender_pk, payload);

        var out = std.json.ObjectMap.init(allocator);
        try out.put("payload_b64", .{ .string = payload });
        try out.put("decrypted", .{ .string = try allocator.dupe(u8, decrypted) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, decrypted) };
    }

    if (std.mem.eql(u8, op, "starknet.selector_from_name")) {
        const name = try getStringFromInputs(inputs, "name");
        const selector = kms_zig.starknet_client.selectors.selectorFromName(name);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("selector", .{ .string = try feltHex(allocator, selector) });
        return .{ .output = .{ .object = out }, .bytes = try dupBytes(allocator, &selector.toBytesBe()) };
    }

    if (std.mem.eql(u8, op, "starknet.serialize_projective_point")) {
        const point = try projectiveFromInputs(inputs, "point");
        const pair = try kms_zig.starknet_client.serialization.serializeProjectivePoint(point);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("x", .{ .string = try feltHex(allocator, pair[0]) });
        try out.put("y", .{ .string = try feltHex(allocator, pair[1]) });
        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, &pair[0].toBytesBe());
        try bytes.appendSlice(allocator, &pair[1].toBytesBe());
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, op, "starknet.u128_u256_roundtrip")) {
        const value = try getU128FromInputs(inputs, "value");
        const pair = kms_zig.starknet_client.serialization.u128ToU256(value);
        const back = try kms_zig.starknet_client.serialization.u256ToU128(pair[0], pair[1]);
        var out = std.json.ObjectMap.init(allocator);
        try out.put("low", .{ .string = try feltHex(allocator, pair[0]) });
        try out.put("high", .{ .string = try feltHex(allocator, pair[1]) });
        try out.put("roundtrip", .{ .string = try std.fmt.allocPrint(allocator, "{}", .{back}) });
        var bytes: std.ArrayList(u8) = .empty;
        try bytes.appendSlice(allocator, &pair[0].toBytesBe());
        try bytes.appendSlice(allocator, &pair[1].toBytesBe());
        var out_u128: [16]u8 = undefined;
        std.mem.writeInt(u128, &out_u128, back, .big);
        try bytes.appendSlice(allocator, &out_u128);
        return .{ .output = .{ .object = out }, .bytes = try bytes.toOwnedSlice(allocator) };
    }

    return error.UnsupportedOperation;
}

fn writeSuccess(allocator: std.mem.Allocator, output: std.json.Value, bytes: []const u8) !void {
    var resp = std.json.ObjectMap.init(allocator);
    defer resp.deinit();

    var meta = std.json.ObjectMap.init(allocator);
    try meta.put("rng_draws", .{ .integer = 0 });
    try meta.put("impl_version", .{ .string = VERSION });

    try resp.put("ok", .{ .bool = true });
    try resp.put("output", output);
    try resp.put("output_bytes_hex", .{ .string = try hexEncodeAlloc(allocator, bytes) });
    try resp.put("error", .null);
    try resp.put("meta", .{ .object = meta });

    const text = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(std.json.Value{ .object = resp }, .{})},
    );
    defer allocator.free(text);
    try std.fs.File.stdout().writeAll(text);
}

fn writeError(allocator: std.mem.Allocator, msg: []const u8) !void {
    var resp = std.json.ObjectMap.init(allocator);
    defer resp.deinit();

    var meta = std.json.ObjectMap.init(allocator);
    try meta.put("rng_draws", .{ .integer = 0 });
    try meta.put("impl_version", .{ .string = VERSION });

    try resp.put("ok", .{ .bool = false });
    try resp.put("output", .null);
    try resp.put("output_bytes_hex", .{ .string = "" });
    try resp.put("error", .{ .string = msg });
    try resp.put("meta", .{ .object = meta });

    const text = try std.fmt.allocPrint(
        allocator,
        "{f}",
        .{std.json.fmt(std.json.Value{ .object = resp }, .{})},
    );
    defer allocator.free(text);
    try std.fs.File.stdout().writeAll(text);
}

fn pointJson(allocator: std.mem.Allocator, point: kms_zig.core.ProjectivePoint) !std.json.ObjectMap {
    const affine = point.toAffine() orelse return error.PointAtInfinity;
    var obj = std.json.ObjectMap.init(allocator);
    try obj.put("x", .{ .string = try feltHex(allocator, affine.x) });
    try obj.put("y", .{ .string = try feltHex(allocator, affine.y) });
    return obj;
}

fn projectiveBytes(allocator: std.mem.Allocator, point: kms_zig.core.ProjectivePoint) ![]u8 {
    const out = try allocator.alloc(u8, 96);
    @memset(out, 0);
    if (point.toAffine()) |affine| {
        @memcpy(out[0..32], &affine.x.toBytesBe());
        @memcpy(out[32..64], &affine.y.toBytesBe());
        out[95] = 1;
    }
    return out;
}

fn projectiveFromInputs(inputs: std.json.Value, key: []const u8) !kms_zig.core.ProjectivePoint {
    if (inputs != .object) return error.InvalidInput;
    const point_val = inputs.object.get(key) orelse return error.InvalidInput;
    return projectiveFromValue(point_val);
}

fn projectiveFromValue(value: std.json.Value) !kms_zig.core.ProjectivePoint {
    if (value != .object) return error.InvalidInput;
    const x = try kms_zig.core.Felt.fromHex(try getString(value.object, "x"));
    const y = try kms_zig.core.Felt.fromHex(try getString(value.object, "y"));
    return kms_zig.core.ProjectivePoint.fromAffine(x, y);
}

fn feltArrayFromInputs(allocator: std.mem.Allocator, inputs: std.json.Value, key: []const u8) ![]kms_zig.core.Felt {
    if (inputs != .object) return error.InvalidInput;
    const arr_val = inputs.object.get(key) orelse return error.InvalidInput;
    if (arr_val != .array) return error.InvalidInput;
    const out = try allocator.alloc(kms_zig.core.Felt, arr_val.array.items.len);
    for (arr_val.array.items, 0..) |item, i| {
        if (item != .string) return error.InvalidInput;
        out[i] = try kms_zig.core.Felt.fromHex(item.string);
    }
    return out;
}

fn feltFromU128(v: u128) kms_zig.core.Felt {
    return kms_zig.core.Felt.fromInt(@as(u256, v)) catch unreachable;
}

fn reqTestAccount(inputs: std.json.Value) !kms_zig.tongo.TongoAccount {
    const private_key = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "private_key"));
    const contract_address = try kms_zig.core.Felt.fromHex(try getStringFromInputs(inputs, "contract_address"));
    var account = kms_zig.tongo.TongoAccount.fromPrivateKey(private_key, contract_address);
    account.state.balance = try getU128FromInputs(inputs, "balance");
    account.state.pending_balance = getU128FromInputsDefault(inputs, "pending_balance", 0);
    account.state.nonce = getU64FromInputsDefault(inputs, "account_nonce", 0);
    return account;
}

fn reqCurrentBalance(inputs: std.json.Value, account: *const kms_zig.tongo.TongoAccount) !kms_zig.she.types.ElGamalCiphertext {
    if (inputs != .object) return error.InvalidInput;

    if (inputs.object.get("current_balance")) |current| {
        if (current != .object) return error.InvalidInput;
        const l_val = current.object.get("l") orelse return error.InvalidInput;
        const r_val = current.object.get("r") orelse return error.InvalidInput;
        const l = try projectiveFromValue(l_val);
        const r = try projectiveFromValue(r_val);
        return .{ .l = l, .r = r };
    }

    const random = if (maybeStringFromInputs(inputs, "current_balance_random")) |hex|
        try kms_zig.core.Felt.fromHex(hex)
    else
        kms_zig.core.Felt.ONE;

    const y = account.keypair.public_key;
    const g = kms_zig.she.curve.GENERATOR;
    const l = kms_zig.she.curve.add(
        kms_zig.she.curve.mul(feltFromU128(account.state.balance), g),
        kms_zig.she.curve.mul(random, y),
    );
    const r = kms_zig.she.curve.mul(random, g);
    return .{ .l = l, .r = r };
}

fn getStringFromInputs(inputs: std.json.Value, key: []const u8) ![]const u8 {
    if (inputs != .object) return error.InvalidInput;
    return getString(inputs.object, key);
}

fn getStringFromInputsDefault(inputs: std.json.Value, key: []const u8, default: []const u8) []const u8 {
    if (inputs != .object) return default;
    const value = inputs.object.get(key) orelse return default;
    return if (value == .string) value.string else default;
}

fn maybeStringFromInputs(inputs: std.json.Value, key: []const u8) ?[]const u8 {
    if (inputs != .object) return null;
    const value = inputs.object.get(key) orelse return null;
    if (value != .string) return null;
    return value.string;
}

fn getU32FromInputs(inputs: std.json.Value, key: []const u8) !u32 {
    if (inputs != .object) return error.InvalidInput;
    const value = inputs.object.get(key) orelse return error.InvalidInput;
    if (value == .integer) return @intCast(value.integer);
    if (value == .string) return std.fmt.parseInt(u32, value.string, 10) catch return error.InvalidInput;
    return error.InvalidInput;
}

fn getU64FromInputs(inputs: std.json.Value, key: []const u8) !u64 {
    if (inputs != .object) return error.InvalidInput;
    const value = inputs.object.get(key) orelse return error.InvalidInput;
    if (value == .integer) return @intCast(value.integer);
    if (value == .string) return std.fmt.parseInt(u64, value.string, 10) catch return error.InvalidInput;
    return error.InvalidInput;
}

fn getU64FromInputsDefault(inputs: std.json.Value, key: []const u8, default: u64) u64 {
    if (inputs != .object) return default;
    const value = inputs.object.get(key) orelse return default;
    return switch (value) {
        .null => default,
        .integer => @intCast(value.integer),
        .string => std.fmt.parseInt(u64, value.string, 10) catch default,
        else => default,
    };
}

fn getU128FromInputs(inputs: std.json.Value, key: []const u8) !u128 {
    if (inputs != .object) return error.InvalidInput;
    const value = inputs.object.get(key) orelse return error.InvalidInput;
    if (value == .integer) return @intCast(value.integer);
    if (value == .string) return std.fmt.parseInt(u128, value.string, 10) catch return error.InvalidInput;
    return error.InvalidInput;
}

fn getU128FromInputsDefault(inputs: std.json.Value, key: []const u8, default: u128) u128 {
    if (inputs != .object) return default;
    const value = inputs.object.get(key) orelse return default;
    return switch (value) {
        .null => default,
        .integer => @intCast(value.integer),
        .string => std.fmt.parseInt(u128, value.string, 10) catch default,
        else => default,
    };
}

fn getString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidInput;
    if (value != .string) return error.InvalidInput;
    return value.string;
}

fn parseSeed32(seed_hex: []const u8) ![32]u8 {
    const raw = strip0x(seed_hex);
    if (raw.len != 64) return error.InvalidInput;
    var out: [32]u8 = undefined;
    _ = try hexDecodeInto(raw, &out);
    return out;
}

fn feltHex(allocator: std.mem.Allocator, felt: kms_zig.core.Felt) ![]u8 {
    const out = try allocator.alloc(u8, 66);
    out[0] = '0';
    out[1] = 'x';
    encodeHex(out[2..], &felt.toBytesBe());
    return out;
}

fn dupBytes(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len);
    @memcpy(out, bytes);
    return out;
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    encodeHex(out, bytes);
    return out;
}

fn hexDecodeAlloc(allocator: std.mem.Allocator, hex_text: []const u8) ![]u8 {
    const raw = strip0x(hex_text);
    if (raw.len % 2 != 0) return error.InvalidInput;
    const out = try allocator.alloc(u8, raw.len / 2);
    _ = try hexDecodeInto(raw, out);
    return out;
}

fn hexDecodeInto(raw: []const u8, out: []u8) ![]u8 {
    if (raw.len != out.len * 2) return error.InvalidInput;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = try hexNibble(raw[i * 2]);
        const lo = try hexNibble(raw[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn encodeHex(dst: []u8, src: []const u8) void {
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const b = src[i];
        dst[i * 2] = nibbleHex((b >> 4) & 0x0f);
        dst[i * 2 + 1] = nibbleHex(b & 0x0f);
    }
}

fn strip0x(input: []const u8) []const u8 {
    if (std.mem.startsWith(u8, input, "0x") or std.mem.startsWith(u8, input, "0X")) return input[2..];
    return input;
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidInput,
    };
}

fn nibbleHex(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}
