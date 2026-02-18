const std = @import("std");

const PARITY_DOMAIN: []const u8 = "kms-parity-v1";
const MAX_STREAM_LEN: usize = 128;

pub const Error = error{
    StreamTooLong,
};

const State = struct {
    seed: [32]u8,
    stream: [MAX_STREAM_LEN]u8,
    stream_len: usize,
    counter: u64,
    block: [32]u8,
    block_offset: usize,
};

var deterministic_state: ?State = null;

pub fn setDeterministic(seed: [32]u8, stream: []const u8) Error!void {
    if (stream.len > MAX_STREAM_LEN) return Error.StreamTooLong;

    var state = State{
        .seed = seed,
        .stream = [_]u8{0} ** MAX_STREAM_LEN,
        .stream_len = stream.len,
        .counter = 0,
        .block = [_]u8{0} ** 32,
        .block_offset = 32,
    };
    std.mem.copyForwards(u8, state.stream[0..stream.len], stream);
    deterministic_state = state;
}

pub fn clearDeterministic() void {
    deterministic_state = null;
}

pub fn fillBytes(out: []u8) void {
    if (deterministic_state) |*state| {
        var written: usize = 0;
        while (written < out.len) {
            if (state.block_offset >= state.block.len) {
                refillBlock(state);
            }

            const available = state.block.len - state.block_offset;
            const needed = out.len - written;
            const chunk = @min(available, needed);
            std.mem.copyForwards(
                u8,
                out[written .. written + chunk],
                state.block[state.block_offset .. state.block_offset + chunk],
            );
            state.block_offset += chunk;
            written += chunk;
        }
        return;
    }

    std.crypto.random.bytes(out);
}

fn refillBlock(state: *State) void {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(PARITY_DOMAIN);
    hasher.update(state.stream[0..state.stream_len]);
    hasher.update(&state.seed);

    var counter_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_bytes, state.counter, .big);
    hasher.update(&counter_bytes);

    hasher.final(&state.block);
    state.block_offset = 0;
    state.counter +%= 1;
}

