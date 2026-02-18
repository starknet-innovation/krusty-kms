const std = @import("std");
const hash = @import("../crypto/hash.zig");

pub const Error = error{
    InvalidMnemonic,
    InvalidLength,
    CryptoFailure,
};

const WORDLIST_TEXT = @embedFile("assets/bip39_english.txt");
const WORDS = parseWordlist(WORDLIST_TEXT);

pub fn generateMnemonic(word_count: u32, out: []u8) Error![]const u8 {
    const entropy_len = wordCountToEntropyLen(word_count) catch return Error.InvalidMnemonic;
    var entropy = [_]u8{0} ** 32;
    std.crypto.random.bytes(entropy[0..entropy_len]);
    return generateMnemonicFromEntropy(entropy[0..entropy_len], out);
}

pub fn generateMnemonicFromEntropy(entropy: []const u8, out: []u8) Error![]const u8 {
    if (!isValidEntropyLen(entropy.len)) return Error.InvalidLength;

    const checksum = hash.sha256(entropy);
    const entropy_bits = entropy.len * 8;
    const checksum_bits = entropy_bits / 32;
    const total_bits = entropy_bits + checksum_bits;
    const word_count = total_bits / 11;

    var offset: usize = 0;
    var word_i: usize = 0;
    while (word_i < word_count) : (word_i += 1) {
        var idx: u16 = 0;
        var bit_i: usize = 0;
        while (bit_i < 11) : (bit_i += 1) {
            idx <<= 1;
            const bit_pos = (word_i * 11) + bit_i;
            if (bitAtEntropyWithChecksum(entropy, checksum, entropy_bits, bit_pos)) {
                idx |= 1;
            }
        }

        const word = WORDS[idx];
        if (word_i != 0) {
            if (offset >= out.len) return Error.InvalidLength;
            out[offset] = ' ';
            offset += 1;
        }
        if (offset + word.len > out.len) return Error.InvalidLength;
        std.mem.copyForwards(u8, out[offset .. offset + word.len], word);
        offset += word.len;
    }

    return out[0..offset];
}

pub fn validateMnemonic(phrase: []const u8) Error!void {
    var words: [24]u16 = undefined;
    const word_count = try parseMnemonicWords(phrase, &words);
    _ = try parseEntropyFromWords(words[0..word_count]);
}

pub fn mnemonicToSeed(phrase: []const u8, passphrase: []const u8) Error![64]u8 {
    try validateMnemonic(phrase);

    var salt = [_]u8{0} ** 256;
    if (8 + passphrase.len > salt.len) return Error.InvalidLength;
    std.mem.copyForwards(u8, salt[0..8], "mnemonic");
    std.mem.copyForwards(u8, salt[8 .. 8 + passphrase.len], passphrase);

    var out: [64]u8 = undefined;
    hash.pbkdf2HmacSha512(phrase, salt[0 .. 8 + passphrase.len], 2048, &out) catch {
        return Error.CryptoFailure;
    };
    return out;
}

fn parseWordlist(comptime text: []const u8) [2048][]const u8 {
    @setEvalBranchQuota(20_000);
    var out: [2048][]const u8 = undefined;
    var start: usize = 0;
    var count: usize = 0;
    var i: usize = 0;
    while (i <= text.len) : (i += 1) {
        if (i == text.len or text[i] == '\n') {
            if (i > start) {
                out[count] = text[start..i];
                count += 1;
            }
            start = i + 1;
        }
    }
    if (count != 2048) @compileError("invalid BIP39 english wordlist size");
    return out;
}

fn wordCountToEntropyLen(word_count: u32) Error!usize {
    return switch (word_count) {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        else => Error.InvalidMnemonic,
    };
}

fn isValidEntropyLen(len: usize) bool {
    return len == 16 or len == 20 or len == 24 or len == 28 or len == 32;
}

fn parseMnemonicWords(phrase: []const u8, out: *[24]u16) Error!usize {
    var count: usize = 0;
    var it = std.mem.tokenizeAny(u8, phrase, " \t\r\n");
    while (it.next()) |word| {
        if (count >= out.len) return Error.InvalidMnemonic;
        out[count] = findWordIndex(word) orelse return Error.InvalidMnemonic;
        count += 1;
    }

    _ = wordCountToEntropyLen(@intCast(count)) catch return Error.InvalidMnemonic;
    return count;
}

fn parseEntropyFromWords(words: []const u16) Error!struct {
    entropy: [32]u8,
    entropy_len: usize,
} {
    const total_bits = words.len * 11;
    const entropy_bits = (total_bits * 32) / 33;
    const checksum_bits = total_bits - entropy_bits;
    const entropy_len = entropy_bits / 8;

    var bitbuf = [_]bool{false} ** 264;
    var write_i: usize = 0;
    for (words) |word_idx| {
        var bit_i: usize = 0;
        while (bit_i < 11) : (bit_i += 1) {
            const shift = 10 - bit_i;
            bitbuf[write_i] = ((word_idx >> @intCast(shift)) & 1) == 1;
            write_i += 1;
        }
    }

    var entropy = [_]u8{0} ** 32;
    var byte_i: usize = 0;
    while (byte_i < entropy_len) : (byte_i += 1) {
        var b: u8 = 0;
        var bit_i: usize = 0;
        while (bit_i < 8) : (bit_i += 1) {
            b <<= 1;
            if (bitbuf[(byte_i * 8) + bit_i]) b |= 1;
        }
        entropy[byte_i] = b;
    }

    const checksum = hash.sha256(entropy[0..entropy_len]);
    var check_i: usize = 0;
    while (check_i < checksum_bits) : (check_i += 1) {
        const expected = bitAtByteSlice(checksum[0..], check_i);
        const found = bitbuf[entropy_bits + check_i];
        if (expected != found) return Error.InvalidMnemonic;
    }

    return .{
        .entropy = entropy,
        .entropy_len = entropy_len,
    };
}

fn findWordIndex(word: []const u8) ?u16 {
    var i: usize = 0;
    while (i < WORDS.len) : (i += 1) {
        if (std.mem.eql(u8, WORDS[i], word)) {
            return @intCast(i);
        }
    }
    return null;
}

fn bitAtByteSlice(bytes: []const u8, bit_pos: usize) bool {
    const byte_i = bit_pos / 8;
    const bit_in_byte = 7 - (bit_pos % 8);
    return ((bytes[byte_i] >> @intCast(bit_in_byte)) & 1) == 1;
}

fn bitAtEntropyWithChecksum(
    entropy: []const u8,
    checksum: [32]u8,
    entropy_bits: usize,
    bit_pos: usize,
) bool {
    if (bit_pos < entropy_bits) {
        return bitAtByteSlice(entropy, bit_pos);
    }
    return bitAtByteSlice(checksum[0..], bit_pos - entropy_bits);
}
