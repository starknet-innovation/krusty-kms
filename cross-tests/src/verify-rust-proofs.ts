/**
 * Cross-SDK verification: verify Rust-generated proofs using the TypeScript
 * @fatsolutions/tongo-sdk verify functions directly.
 *
 * This ensures true cross-SDK compatibility — any prefix computation or
 * protocol-level drift between the Rust SDK and tongo-sdk will be caught.
 *
 * Usage: npx tsx src/verify-rust-proofs.ts [path-to-vectors]
 * Default vectors path: ../../cross-compat-vectors.json
 */

import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { createRequire } from "module";

import {
  ProjectivePoint,
  type CipherBalance,
  type GeneralPrefixData,
} from "@fatsolutions/tongo-sdk";

// The tongo-sdk package.json "exports" only maps ".", so prover subpaths
// are not directly importable. Use createRequire with absolute paths.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

const sdkRoot = resolve(
  __dirname,
  "../node_modules/@fatsolutions/tongo-sdk/dist"
);
const { verifyFund } = require(resolve(sdkRoot, "provers/fund.js"));
const { verifyRollover } = require(resolve(sdkRoot, "provers/rollover.js"));
const { verifyRagequit } = require(resolve(sdkRoot, "provers/ragequit.js"));
const { verifyWithdraw } = require(resolve(sdkRoot, "provers/withdraw.js"));
const { verifyTransfer } = require(resolve(sdkRoot, "provers/transfer.js"));

// ---------------------------------------------------------------------------
// JSON vector types
// ---------------------------------------------------------------------------

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
  proofs: {
    A0: PointJSON;
    A1: PointJSON;
    c0: string;
    s0: string;
    s1: string;
  }[];
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

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

function parsePoint(p: PointJSON): ProjectivePoint {
  return new ProjectivePoint(BigInt(p.x), BigInt(p.y), 1n);
}

function parseCipher(c: CipherJSON): CipherBalance {
  return { L: parsePoint(c.L), R: parsePoint(c.R) };
}

function parsePrefixData(pd: {
  chain_id: string;
  tongo_address: string;
  sender_address: string;
}): GeneralPrefixData {
  return {
    chain_id: BigInt(pd.chain_id),
    tongo_address: BigInt(pd.tongo_address),
    sender_address: BigInt(pd.sender_address),
  };
}

function parseRange(r: RangeProofJSON) {
  return {
    commitments: r.commitments.map((c) => parsePoint(c)),
    proofs: r.proofs.map((p) => ({
      A0: parsePoint(p.A0),
      A1: parsePoint(p.A1),
      c0: BigInt(p.c0),
      s0: BigInt(p.s0),
      s1: BigInt(p.s1),
    })),
  };
}

// ---------------------------------------------------------------------------
// Per-operation verification (delegates to tongo-sdk)
// ---------------------------------------------------------------------------

function verifyFundVector(v: VectorJSON): void {
  const inp = v.inputs as {
    y: PointJSON;
    amount: string;
    nonce: string;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
  };
  const prf = v.proof as { Ax: PointJSON; sx: string };

  verifyFund(
    {
      y: parsePoint(inp.y),
      amount: BigInt(inp.amount),
      nonce: BigInt(inp.nonce),
      prefix_data: parsePrefixData(inp.prefix_data),
    },
    {
      Ax: parsePoint(prf.Ax),
      sx: BigInt(prf.sx),
    }
  );
}

function verifyRolloverVector(v: VectorJSON): void {
  const inp = v.inputs as {
    y: PointJSON;
    nonce: string;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
  };
  const prf = v.proof as { Ax: PointJSON; sx: string };

  verifyRollover(
    {
      y: parsePoint(inp.y),
      nonce: BigInt(inp.nonce),
      prefix_data: parsePrefixData(inp.prefix_data),
    },
    {
      Ax: parsePoint(prf.Ax),
      sx: BigInt(prf.sx),
    }
  );
}

function verifyRagequitVector(v: VectorJSON): void {
  const inp = v.inputs as {
    y: PointJSON;
    nonce: string;
    to: string;
    amount: string;
    currentBalance: CipherJSON;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
  };
  const prf = v.proof as { Ax: PointJSON; AR: PointJSON; sx: string };

  verifyRagequit(
    {
      y: parsePoint(inp.y),
      nonce: BigInt(inp.nonce),
      to: BigInt(inp.to),
      amount: BigInt(inp.amount),
      currentBalance: parseCipher(inp.currentBalance),
      prefix_data: parsePrefixData(inp.prefix_data),
    },
    {
      Ax: parsePoint(prf.Ax),
      AR: parsePoint(prf.AR),
      sx: BigInt(prf.sx),
    }
  );
}

function verifyWithdrawVector(v: VectorJSON): void {
  const inp = v.inputs as {
    y: PointJSON;
    nonce: string;
    to: string;
    amount: string;
    currentBalance: CipherJSON;
    auxiliarCipher: CipherJSON;
    bit_size: number;
    prefix_data: { chain_id: string; tongo_address: string; sender_address: string };
  };
  const prf = v.proof as {
    A_x: PointJSON;
    A_r: PointJSON;
    A: PointJSON;
    A_v: PointJSON;
    sx: string;
    sb: string;
    sr: string;
    range: RangeProofJSON;
  };

  verifyWithdraw(
    {
      y: parsePoint(inp.y),
      nonce: BigInt(inp.nonce),
      to: BigInt(inp.to),
      amount: BigInt(inp.amount),
      currentBalance: parseCipher(inp.currentBalance),
      auxiliarCipher: parseCipher(inp.auxiliarCipher),
      bit_size: inp.bit_size,
      prefix_data: parsePrefixData(inp.prefix_data),
    },
    {
      A_x: parsePoint(prf.A_x),
      A_r: parsePoint(prf.A_r),
      A: parsePoint(prf.A),
      A_v: parsePoint(prf.A_v),
      sx: BigInt(prf.sx),
      sb: BigInt(prf.sb),
      sr: BigInt(prf.sr),
      range: parseRange(prf.range),
    }
  );
}

function verifyTransferVector(v: VectorJSON): void {
  const inp = v.inputs as {
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
  };
  const prf = v.proof as {
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

  verifyTransfer(
    {
      from: parsePoint(inp.from),
      to: parsePoint(inp.to),
      nonce: BigInt(inp.nonce),
      currentBalance: parseCipher(inp.currentBalance),
      transferBalance: parseCipher(inp.transferBalance),
      transferBalanceSelf: parseCipher(inp.transferBalanceSelf),
      auxiliarCipher: parseCipher(inp.auxiliarCipher),
      auxiliarCipher2: parseCipher(inp.auxiliarCipher2),
      bit_size: inp.bit_size,
      prefix_data: parsePrefixData(inp.prefix_data),
    },
    {
      A_x: parsePoint(prf.A_x),
      A_r: parsePoint(prf.A_r),
      A_r2: parsePoint(prf.A_r2),
      A_b: parsePoint(prf.A_b),
      A_b2: parsePoint(prf.A_b2),
      A_v: parsePoint(prf.A_v),
      A_v2: parsePoint(prf.A_v2),
      A_bar: parsePoint(prf.A_bar),
      s_x: BigInt(prf.s_x),
      s_r: BigInt(prf.s_r),
      s_b: BigInt(prf.s_b),
      s_b2: BigInt(prf.s_b2),
      s_r2: BigInt(prf.s_r2),
      range: parseRange(prf.range),
      range2: parseRange(prf.range2),
    }
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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
