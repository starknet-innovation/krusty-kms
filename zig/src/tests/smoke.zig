const std = @import("std");
const kms_zig = @import("kms_zig");

test "u256 parses optional 0x hex" {
    const value = try kms_zig.core.U256.fromHex("0x2a");
    const bytes = value.toBytesBe();

    var i: usize = 0;
    while (i < 31) : (i += 1) {
        try std.testing.expectEqual(@as(u8, 0), bytes[i]);
    }
    try std.testing.expectEqual(@as(u8, 0x2a), bytes[31]);
}

test "felt enforces field modulus upper bound" {
    const modulus_hex = "0x0800000000000011000000000000000000000000000000000000000000000001";
    try std.testing.expectError(error.NotInField, kms_zig.core.Felt.fromHex(modulus_hex));
}

test "felt from bytes accepts small scalar" {
    var bytes = [_]u8{0} ** 32;
    bytes[31] = 7;
    const f = try kms_zig.core.Felt.fromBytesBe(bytes);
    try std.testing.expect(!f.isZero());
}

test "felt mul backend matches bigint modular reference" {
    const modulus = (try kms_zig.core.U256.fromHex(
        "0x0800000000000011000000000000000000000000000000000000000000000001",
    )).toInt();
    var a: u256 = 1;
    var b: u256 = 2;
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        a = @intCast((@as(u512, a) * 1_664_525 + 1_013_904_223) % @as(u512, modulus));
        b = @intCast((@as(u512, b) * 22_695_477 + 1) % @as(u512, modulus));

        const fa = try kms_zig.core.Felt.fromInt(a);
        const fb = try kms_zig.core.Felt.fromInt(b);
        const got = fa.mul(fb).toInt();
        const expected: u256 = @intCast((@as(u512, a) * @as(u512, b)) % @as(u512, modulus));
        try std.testing.expectEqual(expected, got);
    }
}

test "she scalar mul backend matches bigint modular reference" {
    const order = kms_zig.she.scalar.CURVE_ORDER_INT;
    var a: u256 = 7;
    var b: u256 = 11;
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        a = @intCast((@as(u512, a) * 1_103_515_245 + 12_345) % @as(u512, order));
        b = @intCast((@as(u512, b) * 214_013 + 2_531_011) % @as(u512, order));

        const fa = try kms_zig.core.Felt.fromInt(a);
        const fb = try kms_zig.core.Felt.fromInt(b);
        const got = kms_zig.she.scalar.scalarMul(fa, fb).toInt();
        const expected: u256 = @intCast((@as(u512, a) * @as(u512, b)) % @as(u512, order));
        try std.testing.expectEqual(expected, got);
    }
}

test "projective identity roundtrip contract" {
    const id = kms_zig.core.ProjectivePoint.identity();
    try std.testing.expect(id.isIdentity());
    try std.testing.expect(id.toAffine() == null);
}

test "bip44 parse enforces hardened positions" {
    const path = try kms_zig.kms.Bip44Path.parse("m/44'/5454'/0'/0/7");
    try std.testing.expectEqual(@as(u32, 44), path.purpose);
    try std.testing.expectEqual(@as(u32, 5454), path.coin_type);
    try std.testing.expectEqual(@as(u32, 0), path.account);
    try std.testing.expectEqual(@as(u32, 0), path.change);
    try std.testing.expectEqual(@as(u32, 7), path.address_index);

    try std.testing.expectError(
        error.HardenedRequired,
        kms_zig.kms.Bip44Path.parse("m/44/5454'/0'/0/7"),
    );
}

test "pedersen known vector" {
    const x = try kms_zig.core.Felt.fromHex(
        "0x03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb",
    );
    const y = try kms_zig.core.Felt.fromHex(
        "0x0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a",
    );
    const expected = try kms_zig.core.Felt.fromHex(
        "0x030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662",
    );

    const got = try kms_zig.crypto.pedersen.hash(x, y);
    try std.testing.expect(kms_zig.core.Felt.eql(expected, got));
}

test "poseidon hash array vector" {
    const a = try kms_zig.core.Felt.fromHex("0xaa");
    const b = try kms_zig.core.Felt.fromHex("0xbb");
    const c = try kms_zig.core.Felt.fromHex("0xcc");
    const expected = try kms_zig.core.Felt.fromHex(
        "0x2742e049f7e1613e4a014efeec0d742882a798ae0af8b8dd730358c23848775",
    );
    const got = try kms_zig.crypto.poseidon.hashMany(&[_]kms_zig.core.Felt{ a, b, c });
    try std.testing.expect(kms_zig.core.Felt.eql(expected, got));
}

test "poseidon hash many reference set" {
    const one = try kms_zig.core.Felt.fromHex("0x1");
    const two = try kms_zig.core.Felt.fromHex("0x2");
    const three = try kms_zig.core.Felt.fromHex("0x3");
    const four = try kms_zig.core.Felt.fromHex("0x4");

    const h1 = try kms_zig.crypto.poseidon.hashMany(&[_]kms_zig.core.Felt{one});
    try std.testing.expect(kms_zig.core.Felt.eql(
        try kms_zig.core.Felt.fromHex("0x579e8877c7755365d5ec1ec7d3a94a457eff5d1f40482bbe9729c064cdead2"),
        h1,
    ));

    const h2 = try kms_zig.crypto.poseidon.hashMany(&[_]kms_zig.core.Felt{ one, two });
    try std.testing.expect(kms_zig.core.Felt.eql(
        try kms_zig.core.Felt.fromHex("0x371cb6995ea5e7effcd2e174de264b5b407027a75a231a70c2c8d196107f0e7"),
        h2,
    ));

    const h4 = try kms_zig.crypto.poseidon.hashMany(&[_]kms_zig.core.Felt{ one, two, three, four });
    try std.testing.expect(kms_zig.core.Felt.eql(
        try kms_zig.core.Felt.fromHex("0x26e3ad8b876e02bc8a4fc43dad40a8f81a6384083cabffa190bcf40d512ae1d"),
        h4,
    ));
}

test "mnemonic to seed vectors" {
    const phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const seed_empty = try kms_zig.kms.mnemonic.mnemonicToSeed(phrase, "");
    const expected_empty = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    try expectHexEq(&seed_empty, expected_empty);

    const seed_trezor = try kms_zig.kms.mnemonic.mnemonicToSeed(phrase, "TREZOR");
    const expected_trezor = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
    try expectHexEq(&seed_trezor, expected_trezor);
}

test "coin derivation vectors" {
    const mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";

    const stark_priv = try kms_zig.kms.derivation.derivePrivateKeyWithCoinType(
        mnemonic,
        0,
        0,
        9004,
        "",
    );
    const expected_stark = try kms_zig.core.Felt.fromHex(
        "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df",
    );
    try std.testing.expect(kms_zig.core.Felt.eql(expected_stark, stark_priv));

    const tongo_priv = try kms_zig.kms.derivation.derivePrivateKeyWithCoinType(
        mnemonic,
        0,
        0,
        5454,
        "",
    );
    const expected_tongo = try kms_zig.core.Felt.fromHex(
        "0x181c51e06caf24a03c8757ad3af64660fc71e32f9ee0187ca153bd32867c04e",
    );
    try std.testing.expect(kms_zig.core.Felt.eql(expected_tongo, tongo_priv));
}

test "nostr derivation vector" {
    const mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    const kp = try kms_zig.kms.derivation.deriveNostrKeypair(
        mnemonic,
        0,
        0,
        "",
    );
    try expectHexEq(&kp.private_key, "382ee34266a8482e0fd51f085ea4f114c10f90ba27a54cd6dd020c6da291df72");
    try expectHexEq(&kp.public_key_xonly, "29eb921dd3b259edf2e9f2dfdbe2bf7fcebbc2ee8ad4cada7bfa4a13ffa430e9");
}

test "oz account derivation vector" {
    const mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    const kp = try kms_zig.kms.derivation.deriveKeypairWithCoinType(
        mnemonic,
        0,
        0,
        9004,
        "",
    );
    const affine = kp.public_key.toAffine() orelse return error.TestUnexpectedResult;

    const expected_pub_x = try kms_zig.core.Felt.fromHex(
        "0x426212993d56613e1886a4cbc5b58810570023581c2aab0b423277776b79d2e",
    );
    try std.testing.expect(kms_zig.core.Felt.eql(expected_pub_x, affine.x));

    const class_hash = try kms_zig.core.Felt.fromHex(
        "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564",
    );
    const salt = try kms_zig.core.Felt.fromHex("0x0");
    const address = try kms_zig.kms.account.deriveOzAccountAddress(affine.x, class_hash, salt);
    const expected_addr = try kms_zig.core.Felt.fromHex(
        "0x6df2d05138d501f6aafe03c1d95b9ff824e2d96821934cd3d8148801865fefe",
    );
    try std.testing.expect(kms_zig.core.Felt.eql(expected_addr, address));
}

test "ffi abi version" {
    var major: u32 = 0;
    var minor: u32 = 0;
    const rc = kms_zig.ffi.exports.kms_get_abi_version(&major, &minor);
    try std.testing.expectEqual(@as(i32, 0), rc);
    try std.testing.expectEqual(@as(u32, 1), major);
    try std.testing.expectEqual(@as(u32, 0), minor);
}

test "ffi felt hex roundtrip" {
    var felt: kms_zig.ffi.types.KmsFelt = undefined;
    const parse_rc = kms_zig.ffi.exports.kms_felt_from_hex("0x2a", &felt);
    try std.testing.expectEqual(@as(i32, 0), parse_rc);

    var out = [_]u8{0} ** 67;
    var written: usize = 0;
    const print_rc = kms_zig.ffi.exports.kms_felt_to_hex(&felt, &out, out.len, &written);
    try std.testing.expectEqual(@as(i32, 0), print_rc);
    try std.testing.expectEqual(@as(usize, 66), written);
    try std.testing.expectEqualStrings(
        "0x000000000000000000000000000000000000000000000000000000000000002a",
        std.mem.sliceTo(&out, 0),
    );
}

test "ffi validate mnemonic works" {
    const rc_ok = kms_zig.ffi.exports.kms_validate_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    try std.testing.expectEqual(@as(i32, 0), rc_ok);

    const rc_err = kms_zig.ffi.exports.kms_validate_mnemonic("abandon abandon");
    try std.testing.expectEqual(@as(i32, -3), rc_err);
}

test "she poe prove and verify" {
    const x = kms_zig.core.Felt.fromU64(100);
    const prefix = kms_zig.core.Felt.fromU64(42);
    const res = try kms_zig.she.poe.prove(std.testing.allocator, x, prefix);
    const ok = try kms_zig.she.poe.verify(std.testing.allocator, res.y, res.proof, prefix);
    try std.testing.expect(ok);
}

test "she elgamal encrypt verify decrypt" {
    const message = kms_zig.core.Felt.fromU64(10);
    const sk = kms_zig.core.Felt.fromU64(42);
    const pk = kms_zig.she.curve.mul(sk, kms_zig.she.curve.GENERATOR);
    const randomness = kms_zig.core.Felt.fromU64(999);
    const prefix = kms_zig.core.Felt.fromU64(42);

    const enc = try kms_zig.she.elgamal.encrypt(message, pk, randomness, prefix);
    const valid = try kms_zig.she.elgamal.verify(enc.l, enc.r, pk, enc.proof, prefix);
    try std.testing.expect(valid);

    const ciphertext = kms_zig.she.types.ElGamalCiphertext{
        .l = enc.l,
        .r = enc.r,
    };
    const decrypted = try kms_zig.she.elgamal.decrypt(ciphertext, sk);
    const expected = kms_zig.she.curve.mul(message, kms_zig.she.curve.GENERATOR);
    try std.testing.expect(kms_zig.she.curve.pointEq(decrypted, expected));
}

test "she range prove and verify" {
    const g1 = kms_zig.she.curve.GENERATOR;
    const g2 = kms_zig.she.curve.GENERATOR_H;
    const prefix = kms_zig.core.Felt.fromU64(42);

    var prove_res = try kms_zig.she.range.prove(std.testing.allocator, 7, 8, g1, g2, prefix);
    defer prove_res.range.deinit(std.testing.allocator);

    const v = try kms_zig.she.range.verify(std.testing.allocator, prove_res.range, 8, g1, g2, prefix);
    const expected = kms_zig.she.curve.add(
        kms_zig.she.curve.mul(kms_zig.core.Felt.fromU64(7), g1),
        kms_zig.she.curve.mul(prove_res.randomness, g2),
    );
    try std.testing.expect(kms_zig.she.curve.pointEq(v, expected));
}

test "she audit prove and verify" {
    const sk = kms_zig.core.Felt.fromU64(12_345);
    const balance: u128 = 1_000;
    const g = kms_zig.she.curve.GENERATOR;
    const user_pk = kms_zig.she.curve.mul(sk, g);

    const r0 = kms_zig.core.Felt.fromU64(98_765);
    const l0 = kms_zig.she.curve.add(
        kms_zig.she.curve.mul(feltFromU128(balance), g),
        kms_zig.she.curve.mul(r0, user_pk),
    );
    const cipher0 = kms_zig.she.types.ElGamalCiphertext{
        .l = l0,
        .r = kms_zig.she.curve.mul(r0, g),
    };

    const auditor_sk = kms_zig.core.Felt.fromU64(99_999);
    const auditor_pk = kms_zig.she.curve.mul(auditor_sk, g);

    const prove_res = try kms_zig.she.audit.prove(
        std.testing.allocator,
        sk,
        balance,
        cipher0,
        auditor_pk,
    );
    const valid = try kms_zig.she.audit.verify(
        std.testing.allocator,
        prove_res.proof,
        user_pk,
        cipher0,
        prove_res.cipher1,
        auditor_pk,
    );
    try std.testing.expect(valid);
}

test "tongo crypto audit hint roundtrip" {
    const balance: u128 = 1_000_000_000_000_000_000;
    const user_sk = kms_zig.core.Felt.fromU64(42);
    const auditor_sk = kms_zig.core.Felt.fromU64(123);
    const g = kms_zig.she.curve.GENERATOR;
    const user_pk = kms_zig.she.curve.mul(user_sk, g);
    const auditor_pk = kms_zig.she.curve.mul(auditor_sk, g);

    const hint = try kms_zig.tongo.crypto.encryptForAuditor(balance, user_sk, auditor_pk);
    const decrypted = try kms_zig.tongo.crypto.decryptAsAuditor(
        hint.ciphertext,
        hint.nonce,
        auditor_sk,
        user_pk,
    );
    try std.testing.expectEqual(balance, decrypted);
}

test "tongo account from mnemonic" {
    const mnemonic = "habit hope tip crystal because grunt nation idea electric witness alert like";
    const account = try kms_zig.tongo.TongoAccount.fromMnemonic(
        mnemonic,
        0,
        0,
        kms_zig.core.Felt.fromU64(123_456),
        null,
    );
    try std.testing.expect(account.hasViewKey());

    const pk_hex = try account.publicKeyHex(std.testing.allocator);
    defer std.testing.allocator.free(pk_hex);
    try std.testing.expect(std.mem.startsWith(u8, pk_hex, "0x"));
    try std.testing.expectEqual(@as(usize, 130), pk_hex.len);
}

test "tongo core operations smoke" {
    const contract_address = kms_zig.core.Felt.fromU64(123_456);
    var account = kms_zig.tongo.TongoAccount.fromPrivateKey(
        kms_zig.core.Felt.fromU64(42),
        contract_address,
    );
    account.state = .{
        .balance = 1_000,
        .pending_balance = 50,
        .nonce = 0,
    };

    const g = kms_zig.she.curve.GENERATOR;
    const r = kms_zig.core.Felt.fromU64(77);
    const current_balance = kms_zig.she.types.ElGamalCiphertext{
        .l = kms_zig.she.curve.add(
            kms_zig.she.curve.mul(feltFromU128(account.state.balance), g),
            kms_zig.she.curve.mul(r, account.keypair.public_key),
        ),
        .r = kms_zig.she.curve.mul(r, g),
    };

    const fund_proof = try kms_zig.tongo.operations.fund(
        std.testing.allocator,
        &account,
        .{
            .amount = 100,
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
            .current_balance = current_balance,
        },
    );
    try std.testing.expectEqual(@as(u128, 100), fund_proof.amount);

    const rollover_proof = try kms_zig.tongo.operations.rollover(
        std.testing.allocator,
        &account,
        .{
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
        },
    );
    try std.testing.expectEqual(@as(u128, 50), rollover_proof.pending_amount);

    const recipient_key = kms_zig.she.curve.mul(kms_zig.core.Felt.fromU64(99), g);
    var transfer_proof = try kms_zig.tongo.operations.transfer(
        std.testing.allocator,
        &account,
        .{
            .recipient_public_key = recipient_key,
            .amount = 100,
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
            .current_balance = current_balance,
            .bit_size = 16,
        },
    );
    defer transfer_proof.deinit(std.testing.allocator);

    var withdraw_proof = try kms_zig.tongo.operations.withdraw(
        std.testing.allocator,
        &account,
        .{
            .recipient_address = kms_zig.core.Felt.fromU64(999),
            .amount = 100,
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
            .current_balance = current_balance,
            .bit_size = 16,
        },
    );
    defer withdraw_proof.deinit(std.testing.allocator);

    const ragequit_proof = try kms_zig.tongo.operations.ragequit(
        std.testing.allocator,
        &account,
        .{
            .recipient_address = kms_zig.core.Felt.fromU64(999),
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
            .current_balance = current_balance,
        },
    );
    try std.testing.expectEqual(@as(u128, 1_000), ragequit_proof.amount);
}

test "tongo fund with auditor" {
    const contract_address = kms_zig.core.Felt.fromU64(123_456);
    var account = kms_zig.tongo.TongoAccount.fromPrivateKey(
        kms_zig.core.Felt.fromU64(42),
        contract_address,
    );
    account.state.balance = 0;

    const g = kms_zig.she.curve.GENERATOR;
    const r = kms_zig.core.Felt.fromU64(55);
    const current_balance = kms_zig.she.types.ElGamalCiphertext{
        .l = kms_zig.she.curve.mul(r, account.keypair.public_key),
        .r = kms_zig.she.curve.mul(r, g),
    };
    const auditor_key = kms_zig.she.curve.mul(kms_zig.core.Felt.fromU64(888), g);

    const proof = try kms_zig.tongo.operations.fund(
        std.testing.allocator,
        &account,
        .{
            .amount = 100,
            .nonce = kms_zig.core.Felt.fromU64(1),
            .chain_id = kms_zig.core.Felt.fromU64(1),
            .tongo_address = contract_address,
            .auditor_pub_key = auditor_key,
            .current_balance = current_balance,
        },
    );
    try std.testing.expect(proof.audit != null);
}

test "nostr roundtrip encrypt decrypt" {
    const alice_sk = "0x1c0b9a6c83c6b0cbe8eebf5a4e3e4c1e6b6a2f9c1a7b0c6d4f9e1b2c3d4e5f6a";
    const bob_sk = "0x2d1c0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f";

    const alice_pk = try kms_zig.nostr.derivePublicKey(std.testing.allocator, alice_sk);
    defer std.testing.allocator.free(alice_pk);
    const bob_pk = try kms_zig.nostr.derivePublicKey(std.testing.allocator, bob_sk);
    defer std.testing.allocator.free(bob_pk);

    const payload = try kms_zig.nostr.encryptMessage(
        std.testing.allocator,
        alice_sk,
        bob_pk,
        "hello nostr",
    );
    defer std.testing.allocator.free(payload);

    const decrypted = try kms_zig.nostr.decryptMessage(
        std.testing.allocator,
        bob_sk,
        alice_pk,
        payload,
    );
    defer std.testing.allocator.free(decrypted);
    try std.testing.expectEqualStrings("hello nostr", decrypted);
}

test "nostr tampered payload fails mac" {
    const alice_sk = "0x1c0b9a6c83c6b0cbe8eebf5a4e3e4c1e6b6a2f9c1a7b0c6d4f9e1b2c3d4e5f6a";
    const bob_sk = "0x2d1c0a9b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f";

    const alice_pk = try kms_zig.nostr.derivePublicKey(std.testing.allocator, alice_sk);
    defer std.testing.allocator.free(alice_pk);
    const bob_pk = try kms_zig.nostr.derivePublicKey(std.testing.allocator, bob_sk);
    defer std.testing.allocator.free(bob_pk);

    var payload = try kms_zig.nostr.encryptMessage(
        std.testing.allocator,
        alice_sk,
        bob_pk,
        "secure message",
    );
    defer std.testing.allocator.free(payload);
    payload[payload.len - 1] = if (payload[payload.len - 1] == 'A') 'B' else 'A';

    const res = kms_zig.nostr.decryptMessage(std.testing.allocator, bob_sk, alice_pk, payload);
    if (res) |_| {
        return error.TestUnexpectedResult;
    } else |err| {
        try std.testing.expect(
            err == kms_zig.nostr.Error.InvalidPayload or
                err == kms_zig.nostr.Error.MacMismatch,
        );
    }
}

test "starknet selector deterministic" {
    const s1 = kms_zig.starknet_client.selectors.selectorFromName("approve");
    const s2 = kms_zig.starknet_client.selectors.selectorFromName("approve");
    try std.testing.expect(kms_zig.core.Felt.eql(s1, s2));
    try std.testing.expect(!s1.isZero());
}

test "starknet decrypt cipher balance small value" {
    const sk = kms_zig.core.Felt.fromU64(12345);
    const g = kms_zig.she.curve.GENERATOR;
    const public_key = kms_zig.she.curve.mul(sk, g);

    const r = kms_zig.core.Felt.fromU64(999);
    const r_point = kms_zig.she.curve.mul(r, g);
    const y_r = kms_zig.she.curve.mul(r, public_key);
    const g_m = kms_zig.she.curve.mul(kms_zig.core.Felt.fromU64(5), g);
    const l = kms_zig.she.curve.add(g_m, y_r);

    const cipher = kms_zig.starknet_client.CipherBalance{
        .l = l,
        .r = r_point,
    };
    const balance = try kms_zig.starknet_client.types.decryptCipherBalance(sk, cipher, 10_000);
    try std.testing.expectEqual(@as(u128, 5), balance);
}

test "starknet build calls smoke" {
    const erc20 = kms_zig.core.Felt.fromU64(0x123);
    const spender = kms_zig.core.Felt.fromU64(0x456);
    var approve = try kms_zig.starknet_client.operations.buildErc20Approve(
        std.testing.allocator,
        erc20,
        spender,
        1_000,
    );
    defer approve.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), approve.calldata.len);

    const provider = try kms_zig.starknet_client.provider.createProvider(
        std.testing.allocator,
        "https://starknet.example/rpc",
    );
    var provider_mut = provider;
    defer provider_mut.deinit(std.testing.allocator);
    try std.testing.expect(std.mem.startsWith(u8, provider.rpc_url, "https://"));
}

fn expectHexEq(bytes: []const u8, expected_hex: []const u8) !void {
    var out = [_]u8{0} ** 512;
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const b = bytes[i];
        out[i * 2] = toHexNibble((b >> 4) & 0x0f);
        out[i * 2 + 1] = toHexNibble(b & 0x0f);
    }
    try std.testing.expectEqualStrings(expected_hex, out[0 .. bytes.len * 2]);
}

fn toHexNibble(n: u8) u8 {
    return if (n < 10) ('0' + n) else ('a' + (n - 10));
}

fn feltFromU128(value: u128) kms_zig.core.Felt {
    return kms_zig.core.Felt.fromInt(@as(u256, value)) catch unreachable;
}
