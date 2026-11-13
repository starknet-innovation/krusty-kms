// Fixtures and expected patterns exist only in Node, never in target data segments.
const fs = require('node:fs');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

async function instance(file, entropy) {
  // Synthetic entropy remains in Node; the production wasm_js boundary copies
  // directly into the requested WASM destination. Never patch production RNG.
  Object.defineProperty(globalThis, 'crypto', {configurable: true, value: {
    getRandomValues(bytes) { assert.equal(bytes.length, entropy.length); bytes.set(entropy); return bytes; },
  }});
  delete require.cache[require.resolve(file)];
  return require(file).__inspection_wasm;
}

function input(module, bytes) {
  const ptr = module.allocate_input(bytes.length);
  new Uint8Array(module.memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, ptr + bytes.length];
}

function outputRanges(module, metadata) {
  const ranges = new Uint32Array(module.memory.buffer, metadata, 4);
  return [[ranges[0], ranges[0] + ranges[1]], [ranges[2], ranges[2] + ranges[3]]]
    .filter(([start, end]) => end > start);
}

function patterns(entropy, phrase, passphrase) {
  const bits = [...entropy].flatMap(byte => Array.from({length: 8}, (_, i) => (byte >> (7 - i)) & 1));
  const checksum = crypto.createHash('sha256').update(entropy).digest()[0];
  const allBits = [...bits, ...Array.from({length: entropy.length / 4}, (_, i) => (checksum >> (7 - i)) & 1)];
  const indices = Buffer.alloc(allBits.length / 11 * 2);
  for (let i = 0; i < allBits.length / 11; i++) {
    const index = allBits.slice(i * 11, (i + 1) * 11).reduce((n, b) => n * 2 + b, 0);
    indices.writeUInt16LE(index, i * 2);
  }
  const key = phrase.length > 128 ? crypto.createHash('sha512').update(phrase).digest() : phrase;
  const padded = Buffer.alloc(128); key.copy(padded);
  return {
    entropy,
    entropy_bits: Buffer.from(bits),
    word_indices: indices,
    phrase,
    passphrase,
    phrase_sha512: crypto.createHash('sha512').update(phrase).digest(),
    seed: crypto.pbkdf2Sync(phrase, Buffer.concat([Buffer.from('mnemonic'), passphrase]), 2048, 64, 'sha512'),
    hmac_ipad: Buffer.from(padded.map(byte => byte ^ 0x36)),
    hmac_opad: Buffer.from(padded.map(byte => byte ^ 0x5c)),
  };
}

function scan(memory, expected, exclusions) {
  const bytes = Buffer.from(memory.buffer);
  const counts = {};
  for (const [name, pattern] of Object.entries(expected)) {
    let count = 0;
    for (let offset = bytes.indexOf(pattern); offset >= 0; offset = bytes.indexOf(pattern, offset + 1)) {
      if (!exclusions.some(([start, end]) => offset >= start && offset + pattern.length <= end)) count++;
    }
    counts[name] = count;
  }
  return counts;
}

(async () => {
  const [file, mode, report] = process.argv.slice(2);
  const results = [];
  for (const entropyLength of [16, 32]) {
    const entropy = crypto.randomBytes(entropyLength);
    const passphrase = Buffer.from(crypto.randomBytes(24).toString('hex'));
    // Preparation is a separate disposable instance, never the scanned target.
    const preparation = await instance(file, entropy);
    const metadata = preparation.ranges();
    input(preparation, entropy);
    preparation.run(0, entropyLength, 0);
    const [[start, end]] = outputRanges(preparation, metadata);
    const phrase = Buffer.from(new Uint8Array(preparation.memory.buffer, start, end - start));
    const expected = patterns(entropy, phrase, passphrase);
    for (const [operation, name] of ['encode', 'validate', 'seed', 'generate'].entries()) {
      const module = await instance(file, entropy);
      const metadata = module.ranges();
      const liveInput = input(module, Buffer.concat([entropy, phrase, passphrase]));
      module.run(operation, entropyLength, phrase.length);
      // No WASM call occurs after the operation before the memory snapshot.
      const liveOutputs = outputRanges(module, metadata);
      const bytes = Buffer.from(module.memory.buffer);
      for (const [start, end] of [liveInput, ...liveOutputs]) {
        assert(Number.isInteger(start) && start >= 0 && end >= start && end <= bytes.length,
          'registered live range is outside linear memory');
      }
      assert.equal(liveOutputs.length, name === 'validate' ? 0 : 1,
        'wrong number of adapter output ranges');
      for (const [start, end] of liveOutputs) {
        const expectedOutput = name === 'seed' ? expected.seed : phrase;
        assert.equal(end - start, expectedOutput.length, 'wrong adapter output length');
        assert(bytes.subarray(start, end).equals(expectedOutput), 'adapter output does not match expected result');
      }
      const counts = scan(module.memory, expected, [liveInput, ...liveOutputs]);
      const record = {operation: name, entropy_bytes: entropyLength, counts,
        scanned_bytes: module.memory.buffer.byteLength,
        excluded_range_count: [liveInput, ...liveOutputs].length,
        excluded_buffers: [{kind: 'host_input', bytes: liveInput[1] - liveInput[0]},
          ...liveOutputs.map(([a, b]) => ({kind: name === 'seed' ? 'caller_seed_return_slot' : 'returned_phrase', bytes: b - a}))],
        excluded_bytes: [liveInput, ...liveOutputs].reduce((sum, [a, b]) => sum + b - a, 0)};
      results.push(record);
    }
  }
  // Only counts are logged; never fixtures, matches, or recovered secrets.
  let passed = true;
  for (const record of results) {
    const detected = Object.values(record.counts).some(count => count > 0);
    const valid = mode === 'clean' ? !detected : detected;
    passed &&= valid;
    console.log(`${record.operation}/${record.entropy_bytes}: mode=${mode} valid=${valid}`);
  }
  fs.writeFileSync(report, JSON.stringify({status: passed ? 'passed' : 'failed', mode, cases: results}, null, 2) + '\n');
  assert(passed, mode === 'clean' ? 'searched remnants found outside registered live buffers' : 'inconclusive: a disabled-scrub case left no searched remnant');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
