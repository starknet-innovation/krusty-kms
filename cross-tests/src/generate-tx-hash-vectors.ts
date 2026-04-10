/**
 * Cross-language transaction hash parity verification.
 *
 * Computes transaction hashes using starknet.js v6 for the same inputs
 * defined in `crates/kms/tests/fixtures/tx_hash_parity_vectors.json`.
 *
 * Run with:
 *   npx tsx src/generate-tx-hash-vectors.ts
 *
 * The output hashes should match those in the Rust fixture file. If they
 * diverge, one of the implementations has a bug.
 */

import { hash, constants } from "starknet";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ---------------------------------------------------------------------------
// Load fixture
// ---------------------------------------------------------------------------

const FIXTURE_PATH = resolve(
  __dirname,
  "../../crates/kms/tests/fixtures/tx_hash_parity_vectors.json"
);

interface GasBounds {
  max_amount: string;
  max_price_per_unit: string;
}

interface InvokeV1Vector {
  name: string;
  sender_address: string;
  calldata: string[];
  max_fee: string;
  chain_id: string;
  nonce: string;
  expected_hash: string;
}

interface InvokeV3Vector {
  name: string;
  sender_address: string;
  calldata: string[];
  chain_id: string;
  nonce: string;
  tip: string;
  l1_gas: GasBounds;
  l2_gas: GasBounds;
  l1_data_gas: GasBounds;
  paymaster_data: string[];
  nonce_da_mode: number;
  fee_da_mode: number;
  account_deployment_data: string[];
  expected_hash: string;
}

interface DeployAccountV1Vector {
  name: string;
  contract_address: string;
  class_hash: string;
  constructor_calldata: string[];
  salt: string;
  max_fee: string;
  chain_id: string;
  nonce: string;
  expected_hash: string;
}

interface DeclareV2Vector {
  name: string;
  sender_address: string;
  class_hash: string;
  max_fee: string;
  chain_id: string;
  nonce: string;
  compiled_class_hash: string;
  expected_hash: string;
}

interface Fixture {
  description: string;
  spec_version: string;
  vectors: {
    invoke_v1: InvokeV1Vector[];
    invoke_v3: InvokeV3Vector[];
    deploy_account_v1: DeployAccountV1Vector[];
    declare_v2: DeclareV2Vector[];
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assertEqual(testName: string, actual: string, expected: string): void {
  const normActual = actual.toLowerCase();
  const normExpected = expected.toLowerCase();
  if (normActual === normExpected) {
    console.log(`  PASS ${testName}`);
    passed++;
  } else {
    console.error(
      `  FAIL ${testName}\n       expected: ${expected}\n       actual:   ${actual}`
    );
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8"));

  console.log("Transaction hash parity verification (starknet.js v6)\n");
  console.log(`Fixture: ${fixture.description}`);
  console.log(`Spec version: ${fixture.spec_version}\n`);

  // -------------------------------------------------------------------------
  // Invoke V1
  // -------------------------------------------------------------------------
  console.log("Invoke V1:");
  for (const v of fixture.vectors.invoke_v1) {
    const computed = hash.calculateInvokeTransactionHash({
      senderAddress: v.sender_address,
      version: "0x1",
      compiledCalldata: v.calldata,
      maxFee: v.max_fee,
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
    });
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Invoke V3
  // -------------------------------------------------------------------------
  console.log("Invoke V3:");
  for (const v of fixture.vectors.invoke_v3) {
    const computed = hash.calculateInvokeTransactionHash({
      senderAddress: v.sender_address,
      version: "0x3",
      compiledCalldata: v.calldata,
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
      accountDeploymentData: v.account_deployment_data,
      nonceDataAvailabilityMode: v.nonce_da_mode,
      feeDataAvailabilityMode: v.fee_da_mode,
      resourceBounds: {
        l1_gas: {
          max_amount: v.l1_gas.max_amount,
          max_price_per_unit: v.l1_gas.max_price_per_unit,
        },
        l2_gas: {
          max_amount: v.l2_gas.max_amount,
          max_price_per_unit: v.l2_gas.max_price_per_unit,
        },
        l1_data_gas: {
          max_amount: v.l1_data_gas.max_amount,
          max_price_per_unit: v.l1_data_gas.max_price_per_unit,
        },
      },
      tip: v.tip,
      paymasterData: v.paymaster_data,
    });
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Deploy Account V1
  // -------------------------------------------------------------------------
  console.log("Deploy Account V1:");
  for (const v of fixture.vectors.deploy_account_v1) {
    const computed = hash.calculateDeployAccountTransactionHash({
      contractAddress: v.contract_address,
      classHash: v.class_hash,
      constructorCalldata: v.constructor_calldata,
      salt: v.salt,
      version: "0x1",
      maxFee: v.max_fee,
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
    });
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Declare V2
  // -------------------------------------------------------------------------
  console.log("Declare V2:");
  for (const v of fixture.vectors.declare_v2) {
    const computed = hash.calculateDeclareTransactionHash({
      senderAddress: v.sender_address,
      version: "0x2",
      classHash: v.class_hash,
      maxFee: v.max_fee,
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
      compiledClassHash: v.compiled_class_hash,
    });
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log(`\nResults: ${passed} passed, ${failed} failed`);

  if (failed > 0) {
    process.exit(1);
  }
}

main();
