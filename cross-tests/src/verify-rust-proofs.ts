/**
 * Cross-SDK verification: verify Rust-generated proofs using the TypeScript @fatsolutions/she
 * cryptographic primitives (same library used by tongo-sdk internally).
 *
 * This implements the same verification logic as tongo-sdk's verifyFund, verifyRollover,
 * and verifyRagequit - using the exact same prefix computation and challenge derivation.
 *
 * Usage: npx tsx src/verify-rust-proofs.ts [path-to-vectors]
 * Default vectors path: ../cross-compat-vectors.json
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

import { ProjectivePoint, CURVE } from "@scure/starknet";
import { poseidonHashMany } from "@scure/starknet";
import { compute_challenge } from "@fatsolutions/she";
import { poe } from "@fatsolutions/she/protocols";

const __dirname = dirname(fileURLToPath(import.meta.url));

const GENERATOR = new ProjectivePoint(CURVE.Gx, CURVE.Gy, 1n);

// Cairo string constants (must match both Rust and TS SDKs)
const FUND_CAIRO_STRING = 0x66756e64n; // 'fund'
const ROLLOVER_CAIRO_STRING = 0x726f6c6c6f766572n; // 'rollover'
const RAGEQUIT_CAIRO_STRING = 0x7261676571756974n; // 'ragequit'

interface PointJSON {
  x: string;
  y: string;
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

// ---- Fund verification ----
// Matches tongo-sdk/src/provers/fund.ts:verifyFund

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
// Matches tongo-sdk/src/provers/rollover.ts:verifyRollover

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
// Matches tongo-sdk/src/provers/ragequit.ts:verifyRagequit

function verifyRagequitVector(v: VectorJSON): void {
  const inputs = v.inputs as {
    y: PointJSON;
    nonce: string;
    to: string;
    amount: string;
    currentBalance: { L: PointJSON; R: PointJSON };
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

  // Verify POE for y = g^x
  const res1 = poe._verify(y, GENERATOR, Ax, c, sx);
  if (!res1) {
    throw new Error("verifyRagequit: POE y verification failed");
  }

  // Verify POE for R: L1 - g^amount = R1^x  =>  (L1 - g^amount) = R1^x
  const amount = BigInt(inputs.amount);
  const L = L1.subtract(GENERATOR.multiply(amount));
  const res2 = poe._verify(L, R1, AR, c, sx);
  if (!res2) {
    throw new Error("verifyRagequit: POE R verification failed");
  }
}

async function main() {
  const vectorsPath =
    process.argv[2] || resolve(__dirname, "../../cross-compat-vectors.json");
  const content = readFileSync(vectorsPath, "utf-8");
  const data: VectorsFile = JSON.parse(content);

  console.log(
    `Cross-SDK verification: ${data.totalVectors} vectors`
  );
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
