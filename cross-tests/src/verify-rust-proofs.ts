/**
 * Cross-SDK verification: verify Rust-generated proofs using the TypeScript @fatsolutions/she
 * cryptographic primitives (same library used by tongo-sdk internally).
 *
 * This implements the same verification logic as tongo-sdk's verify functions
 * using the exact same prefix computation and challenge derivation.
 *
 * Usage: npx tsx src/verify-rust-proofs.ts [path-to-vectors]
 * Default vectors path (resolved from this src directory): ../../cross-compat-vectors.json
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

import { poseidonHashMany, CURVE } from "@scure/starknet";
import { ProjectivePoint, compute_challenge } from "@fatsolutions/she";
import {
  poe,
  range as SHE_range,
  SameEncryptUnknownRandom,
  ElGamal,
  SameEncrypt,
} from "@fatsolutions/she/protocols";

const __dirname = dirname(fileURLToPath(import.meta.url));

const GENERATOR = new ProjectivePoint(CURVE.Gx, CURVE.Gy, 1n);
// Secondary generator (must match Rust StarkCurve::generator_h())
const SECONDARY_GENERATOR = new ProjectivePoint(
  627088272801405713560985229077786158610581355215145837257248988047835443922n,
  962306405833205337611861169387935900858447421343428280515103558221889311122n,
  1n
);

// Cairo string constants (must match both Rust and TS SDKs)
const FUND_CAIRO_STRING = 0x66756e64n; // 'fund'
const ROLLOVER_CAIRO_STRING = 0x726f6c6c6f766572n; // 'rollover'
const RAGEQUIT_CAIRO_STRING = 0x7261676571756974n; // 'ragequit'
const WITHDRAW_CAIRO_STRING = 0x7769746864726177n; // 'withdraw'
const TRANSFER_CAIRO_STRING = 0x7472616e73666572n; // 'transfer'

interface PointJSON {
  x: string;
  y: string;
}

interface CipherJSON {
  L: PointJSON;
  R: PointJSON;
}

interface RangeProofJSON {
  commitments: PointJSON[];
  proofs: { A0: PointJSON; A1: PointJSON; c0: string; s0: string; s1: string }[];
}

interface VectorJSON {
  operation: string;
  name: string;
  description: string;
  inputs: Record<string, unknown>;
  proof: Record<string, unknown>;
}

interface VectorsFile {
  description: string;
  totalVectors: number;
  vectors: VectorJSON[];
}

function parsePoint(p: PointJSON): ProjectivePoint {
  return new ProjectivePoint(BigInt(p.x), BigInt(p.y), 1n);
}

function computePrefix(seq: bigint[]): bigint {
  return poseidonHashMany(seq);
}

function verifyRangeProof(
  rangeProof: RangeProofJSON,
  bitSize: number,
  initialPrefix: bigint
): false | ProjectivePoint {
  const commitments = rangeProof.commitments.map((c) => parsePoint(c));
  const inputs: SHE_range.RangeInputs = {
    g1: GENERATOR,
    g2: SECONDARY_GENERATOR,
    bit_size: bitSize,
    commitments,
  };
  const proof: SHE_range.RangeProof = {
    proofs: rangeProof.proofs.map((pi, index) => ({
      A0: parsePoint(pi.A0),
      A1: parsePoint(pi.A1),
      prefix: initialPrefix + BigInt(index),
      c0: BigInt(pi.c0),
      s0: BigInt(pi.s0),
      s1: BigInt(pi.s1),
    })),
  };
  return SHE_range.verify(inputs, proof);
}

// ---- Fund verification ----

function verifyFundVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    y: PointJSON;
    amount: string;
    nonce: string;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
    relay_data: { fee_to_sender: string };
  };
  const proof = v.proof as { Ax: PointJSON; sx: string };

  const y = parsePoint(inputs.y);
  const Ax = parsePoint(proof.Ax);
  const sx = BigInt(proof.sx);

  const yAffine = y.toAffine();
  const prefix = computePrefix([
    BigInt(inputs.prefix_data.chain_id),
    BigInt(inputs.prefix_data.tongo_address),
    BigInt(inputs.prefix_data.sender_address),
    BigInt(inputs.relay_data.fee_to_sender),
    FUND_CAIRO_STRING,
    yAffine.x,
    yAffine.y,
    BigInt(inputs.amount),
    BigInt(inputs.nonce),
  ]);

  const c = compute_challenge(prefix, [Ax]);
  const res = poe._verify(y, GENERATOR, Ax, c, sx);
  if (!res) {
    throw new Error("verifyFund: POE verification failed");
  }
}

// ---- Rollover verification ----

function verifyRolloverVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    y: PointJSON;
    nonce: string;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
  };
  const proof = v.proof as { Ax: PointJSON; sx: string };

  const y = parsePoint(inputs.y);
  const Ax = parsePoint(proof.Ax);
  const sx = BigInt(proof.sx);

  const yAffine = y.toAffine();
  const prefix = computePrefix([
    BigInt(inputs.prefix_data.chain_id),
    BigInt(inputs.prefix_data.tongo_address),
    BigInt(inputs.prefix_data.sender_address),
    ROLLOVER_CAIRO_STRING,
    yAffine.x,
    yAffine.y,
    BigInt(inputs.nonce),
  ]);

  const c = compute_challenge(prefix, [Ax]);
  const res = poe._verify(y, GENERATOR, Ax, c, sx);
  if (!res) {
    throw new Error("verifyRollover: POE verification failed");
  }
}

// ---- Ragequit verification ----

function verifyRagequitVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    y: PointJSON;
    nonce: string;
    to: string;
    amount: string;
    currentBalance: CipherJSON;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
    relay_data: { fee_to_sender: string };
  };
  const proof = v.proof as { Ax: PointJSON; AR: PointJSON; sx: string };

  const y = parsePoint(inputs.y);
  const Ax = parsePoint(proof.Ax);
  const AR = parsePoint(proof.AR);
  const sx = BigInt(proof.sx);
  const L1 = parsePoint(inputs.currentBalance.L);
  const R1 = parsePoint(inputs.currentBalance.R);

  const yAffine = y.toAffine();
  const L1Affine = L1.toAffine();
  const R1Affine = R1.toAffine();

  const prefix = computePrefix([
    BigInt(inputs.prefix_data.chain_id),
    BigInt(inputs.prefix_data.tongo_address),
    BigInt(inputs.prefix_data.sender_address),
    BigInt(inputs.relay_data.fee_to_sender),
    RAGEQUIT_CAIRO_STRING,
    yAffine.x,
    yAffine.y,
    BigInt(inputs.nonce),
    BigInt(inputs.amount),
    BigInt(inputs.to),
    L1Affine.x,
    L1Affine.y,
    R1Affine.x,
    R1Affine.y,
  ]);

  const c = compute_challenge(prefix, [Ax, AR]);

  const res1 = poe._verify(y, GENERATOR, Ax, c, sx);
  if (!res1) {
    throw new Error("verifyRagequit: POE y verification failed");
  }

  const amount = BigInt(inputs.amount);
  const L = L1.subtract(GENERATOR.multiply(amount));
  const res2 = poe._verify(L, R1, AR, c, sx);
  if (!res2) {
    throw new Error("verifyRagequit: POE R verification failed");
  }
}

// ---- Withdraw verification ----
// Matches tongo-sdk/src/provers/withdraw.ts:verifyWithdraw

function verifyWithdrawVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    y: PointJSON;
    nonce: string;
    to: string;
    amount: string;
    currentBalance: CipherJSON;
    auxiliarCipher: CipherJSON;
    bit_size: number;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
    relay_data: { fee_to_sender: string };
  };
  const proof = v.proof as {
    A_x: PointJSON;
    A_r: PointJSON;
    A: PointJSON;
    A_v: PointJSON;
    sx: string;
    sb: string;
    sr: string;
    range: RangeProofJSON;
  };

  const y = parsePoint(inputs.y);
  const L0 = parsePoint(inputs.currentBalance.L);
  const R0 = parsePoint(inputs.currentBalance.R);
  const V = parsePoint(inputs.auxiliarCipher.L);
  const R_aux = parsePoint(inputs.auxiliarCipher.R);
  const A_x = parsePoint(proof.A_x);
  const A_r = parsePoint(proof.A_r);
  const A = parsePoint(proof.A);
  const A_v = parsePoint(proof.A_v);
  const sx = BigInt(proof.sx);
  const sb = BigInt(proof.sb);
  const sr = BigInt(proof.sr);
  const bitSize = inputs.bit_size;

  const yAffine = y.toAffine();
  const L0Affine = L0.toAffine();
  const R0Affine = R0.toAffine();
  const VAffine = V.toAffine();
  const RAuxAffine = R_aux.toAffine();

  const prefix = computePrefix([
    BigInt(inputs.prefix_data.chain_id),
    BigInt(inputs.prefix_data.tongo_address),
    BigInt(inputs.prefix_data.sender_address),
    BigInt(inputs.relay_data.fee_to_sender),
    WITHDRAW_CAIRO_STRING,
    yAffine.x,
    yAffine.y,
    BigInt(inputs.nonce),
    BigInt(inputs.amount),
    BigInt(inputs.to),
    L0Affine.x,
    L0Affine.y,
    R0Affine.x,
    R0Affine.y,
    VAffine.x,
    VAffine.y,
    RAuxAffine.x,
    RAuxAffine.y,
  ]);

  const c = compute_challenge(prefix, [A_x, A_r, A, A_v]);

  // Subtract withdraw amount from L0
  const L0_minus_amount = L0.subtract(GENERATOR.multiply(BigInt(inputs.amount)));

  // Verify range proof for V
  const V_proof = verifyRangeProof(proof.range, bitSize, prefix);
  if (V_proof === false) throw new Error("verifyWithdraw: range proof failed");
  if (!V.equals(V_proof)) throw new Error("verifyWithdraw: V mismatch");

  // Verify SameEncryptUnknownRandom: (L0-g^amount, R0) encrypts same as (V, R_aux)
  const sameEncryptRes = SameEncryptUnknownRandom.verify(
    { L1: L0_minus_amount, R1: R0, L2: V, R2: R_aux, g: GENERATOR, y1: y, y2: SECONDARY_GENERATOR },
    { Ax: A_x, AL1: A, AL2: A_v, AR2: A_r, c, sb, sx, sr2: sr }
  );
  if (!sameEncryptRes) {
    throw new Error("verifyWithdraw: SameEncryptUnknownRandom failed");
  }
}

// ---- Transfer verification ----
// Matches tongo-sdk/src/provers/transfer.ts:verifyTransfer

function verifyTransferVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    from: PointJSON;
    to: PointJSON;
    nonce: string;
    currentBalance: CipherJSON;
    transferBalance: CipherJSON;
    transferBalanceSelf: CipherJSON;
    auxiliarCipher: CipherJSON;
    auxiliarCipher2: CipherJSON;
    bit_size: number;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
    relay_data: { fee_to_sender: string };
  };
  const proof = v.proof as {
    A_x: PointJSON;
    A_r: PointJSON;
    A_r2: PointJSON;
    A_b: PointJSON;
    A_b2: PointJSON;
    A_v: PointJSON;
    A_v2: PointJSON;
    A_bar: PointJSON;
    s_x: string;
    s_r: string;
    s_b: string;
    s_b2: string;
    s_r2: string;
    range: RangeProofJSON;
    range2: RangeProofJSON;
  };

  const from = parsePoint(inputs.from);
  const to = parsePoint(inputs.to);
  const CL = parsePoint(inputs.currentBalance.L);
  const CR = parsePoint(inputs.currentBalance.R);
  const L = parsePoint(inputs.transferBalanceSelf.L);
  const R = parsePoint(inputs.transferBalanceSelf.R);
  const L_bar = parsePoint(inputs.transferBalance.L);
  const R_bar = parsePoint(inputs.transferBalance.R);
  const V = parsePoint(inputs.auxiliarCipher.L);
  const R_aux = parsePoint(inputs.auxiliarCipher.R);
  const V2 = parsePoint(inputs.auxiliarCipher2.L);
  const R_aux2 = parsePoint(inputs.auxiliarCipher2.R);

  const A_x = parsePoint(proof.A_x);
  const A_r = parsePoint(proof.A_r);
  const A_r2 = parsePoint(proof.A_r2);
  const A_b = parsePoint(proof.A_b);
  const A_b2 = parsePoint(proof.A_b2);
  const A_v = parsePoint(proof.A_v);
  const A_v2 = parsePoint(proof.A_v2);
  const A_bar = parsePoint(proof.A_bar);
  const s_x = BigInt(proof.s_x);
  const s_r = BigInt(proof.s_r);
  const s_b = BigInt(proof.s_b);
  const s_b2 = BigInt(proof.s_b2);
  const s_r2 = BigInt(proof.s_r2);
  const bitSize = inputs.bit_size;

  const fromAffine = from.toAffine();
  const toAffine = to.toAffine();
  const CLAffine = CL.toAffine();
  const CRAffine = CR.toAffine();
  const LAffine = L.toAffine();
  const RAffine = R.toAffine();
  const LBarAffine = L_bar.toAffine();
  const RBarAffine = R_bar.toAffine();
  const VAffine = V.toAffine();
  const RAuxAffine = R_aux.toAffine();
  const V2Affine = V2.toAffine();
  const RAux2Affine = R_aux2.toAffine();

  const prefix = computePrefix([
    BigInt(inputs.prefix_data.chain_id),
    BigInt(inputs.prefix_data.tongo_address),
    BigInt(inputs.prefix_data.sender_address),
    BigInt(inputs.relay_data.fee_to_sender),
    TRANSFER_CAIRO_STRING,
    fromAffine.x,
    fromAffine.y,
    toAffine.x,
    toAffine.y,
    BigInt(inputs.nonce),
    CLAffine.x,
    CLAffine.y,
    CRAffine.x,
    CRAffine.y,
    LAffine.x,
    LAffine.y,
    RAffine.x,
    RAffine.y,
    LBarAffine.x,
    LBarAffine.y,
    RBarAffine.x,
    RBarAffine.y,
    VAffine.x,
    VAffine.y,
    RAuxAffine.x,
    RAuxAffine.y,
    V2Affine.x,
    V2Affine.y,
    RAux2Affine.x,
    RAux2Affine.y,
  ]);

  const c = compute_challenge(prefix, [A_x, A_r, A_r2, A_b, A_b2, A_v, A_v2, A_bar]);

  // 1. Verify POE for from = g^x
  let res = poe._verify(from, GENERATOR, A_x, c, s_x);
  if (!res) throw new Error("verifyTransfer: POE for y failed");

  // 2. Verify SameEncrypt: (L,R) and (L_bar, R_bar) encrypt the same amount
  res = SameEncrypt.verify(
    { L1: L, R1: R, L2: L_bar, R2: R_bar, g: GENERATOR, y1: from, y2: to },
    { AL1: A_b, AR1: A_r, AL2: A_bar, AR2: A_r, c, sb: s_b, sr1: s_r, sr2: s_r }
  );
  if (!res) throw new Error("verifyTransfer: SameEncrypt failed");

  // 3. Verify range proof for transfer amount
  const V_proof = verifyRangeProof(proof.range, bitSize, prefix);
  if (V_proof === false) throw new Error("verifyTransfer: range proof 1 failed");
  if (!V.equals(V_proof)) throw new Error("verifyTransfer: V mismatch");

  // 4. Verify ElGamal for (V, R_aux)
  res = ElGamal.verify(
    { L: V, R: R_aux, g1: GENERATOR, g2: SECONDARY_GENERATOR },
    { AL: A_v, AR: A_r, c, sb: s_b, sr: s_r }
  );
  if (!res) throw new Error("verifyTransfer: ElGamal failed");

  // 5. Compute leftover balance cipher: (L0, R0) = (CL - L, CR - R)
  const L0 = CL.subtract(L);
  const R0 = CR.subtract(R);

  // 6. Verify range proof for leftover balance
  const V2_proof = verifyRangeProof(proof.range2, bitSize, prefix);
  if (V2_proof === false) throw new Error("verifyTransfer: range proof 2 failed");
  if (!V2.equals(V2_proof)) throw new Error("verifyTransfer: V2 mismatch");

  // 7. Verify SameEncryptUnknownRandom for leftover
  res = SameEncryptUnknownRandom.verify(
    { L1: L0, R1: R0, L2: V2, R2: R_aux2, g: GENERATOR, y1: from, y2: SECONDARY_GENERATOR },
    { Ax: A_x, AL1: A_b2, AL2: A_v2, AR2: A_r2, c, sb: s_b2, sx: s_x, sr2: s_r2 }
  );
  if (!res) throw new Error("verifyTransfer: SameEncryptUnknownRandom failed");
}

async function main() {
  const vectorsPath =
    process.argv[2] || resolve(__dirname, "../../cross-compat-vectors.json");
  const content = readFileSync(vectorsPath, "utf-8");
  const data: VectorsFile = JSON.parse(content);

  if (data.vectors.length !== data.totalVectors) {
    throw new Error(
      `Vector file '${vectorsPath}' is inconsistent: expected totalVectors=${data.totalVectors}, but found ${data.vectors.length} vector entries`
    );
  }
  console.log(`Cross-SDK verification: ${data.totalVectors} vectors`);
  console.log(`${data.description}\n`);

  let passed = 0;
  let failed = 0;

  for (const v of data.vectors) {
    try {
      switch (v.operation) {
        case "fund":
          verifyFundVector(v);
          break;
        case "rollover":
          verifyRolloverVector(v);
          break;
        case "ragequit":
          verifyRagequitVector(v);
          break;
        case "withdraw":
          verifyWithdrawVector(v);
          break;
        case "transfer":
          verifyTransferVector(v);
          break;
        default:
          console.log(`  SKIP ${v.name}: unknown operation '${v.operation}'`);
          continue;
      }
      console.log(`  PASS ${v.name}`);
      passed++;
    } catch (e) {
      console.error(`  FAIL ${v.name}: ${(e as Error).message}`);
      failed++;
    }
  }

  console.log(`\nResults: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("Fatal error:", e);
  process.exit(1);
});
