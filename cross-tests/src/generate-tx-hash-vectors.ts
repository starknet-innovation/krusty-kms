/**
 * Cross-language transaction hash parity verification.
 *
 * Computes transaction hashes using starknet@10.0.2 for the same inputs
 * defined in `crates/kms/tests/fixtures/tx_hash_parity_vectors.json`.
 *
 * Run with:
 *   npx tsx src/generate-tx-hash-vectors.ts
 *
 * The output hashes should match those in the Rust fixture file. If they
 * diverge, one of the implementations has a bug.
 */

import { hash, v2hash, constants } from "starknet-10";
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
  proof_facts?: string[];
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

interface DeployAccountV3Vector {
  name: string;
  contract_address: string;
  class_hash: string;
  constructor_calldata: string[];
  salt: string;
  chain_id: string;
  nonce: string;
  tip: string;
  l1_gas: GasBounds;
  l2_gas: GasBounds;
  l1_data_gas: GasBounds;
  paymaster_data: string[];
  nonce_da_mode: number;
  fee_da_mode: number;
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

interface DeclareV3Vector {
  name: string;
  sender_address: string;
  class_hash: string;
  compiled_class_hash: string;
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

interface Fixture {
  description: string;
  spec_version: string;
  vectors: {
    invoke_v1: InvokeV1Vector[];
    invoke_v3: InvokeV3Vector[];
    deploy_account_v1: DeployAccountV1Vector[];
    deploy_account_v3: DeployAccountV3Vector[];
    declare_v2: DeclareV2Vector[];
    declare_v3: DeclareV3Vector[];
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assertEqual(testName: string, actual: string, expected: string): void {
  const normActual = normalizeHex(actual);
  const normExpected = normalizeHex(expected);
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

function normalizeHex(value: string): string {
  if (!value.startsWith("0x") && !value.startsWith("0X")) {
    return value.toLowerCase();
  }
  return `0x${BigInt(value).toString(16)}`;
}

function gasBounds(gas: GasBounds) {
  return {
    max_amount: BigInt(gas.max_amount),
    max_price_per_unit: BigInt(gas.max_price_per_unit),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const fixture: Fixture = JSON.parse(readFileSync(FIXTURE_PATH, "utf-8"));

  console.log("Transaction hash parity verification (starknet@10.0.2)\n");
  console.log(`Fixture: ${fixture.description}`);
  console.log(`Spec version: ${fixture.spec_version}\n`);

  // -------------------------------------------------------------------------
  // Invoke V1
  // -------------------------------------------------------------------------
  console.log("Invoke V1:");
  for (const v of fixture.vectors.invoke_v1) {
    const computed = v2hash.calculateTransactionHash(
      v.sender_address,
      "0x1",
      v.calldata,
      v.max_fee,
      v.chain_id as constants.StarknetChainId,
      v.nonce
    );
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Invoke V3
  // -------------------------------------------------------------------------
  console.log("Invoke V3:");
  for (const v of fixture.vectors.invoke_v3) {
    const args: any = {
      senderAddress: v.sender_address,
      version: "0x3",
      compiledCalldata: v.calldata,
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
      accountDeploymentData: v.account_deployment_data,
      nonceDataAvailabilityMode: v.nonce_da_mode,
      feeDataAvailabilityMode: v.fee_da_mode,
      resourceBounds: {
        l1_gas: gasBounds(v.l1_gas),
        l2_gas: gasBounds(v.l2_gas),
        l1_data_gas: gasBounds(v.l1_data_gas),
      },
      tip: v.tip,
      paymasterData: v.paymaster_data,
    };
    if (v.proof_facts !== undefined) {
      args.proofFacts = v.proof_facts;
    }
    const computed = hash.calculateInvokeTransactionHash(args);
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Deploy Account V1
  // -------------------------------------------------------------------------
  console.log("Deploy Account V1:");
  for (const v of fixture.vectors.deploy_account_v1) {
    const computed = v2hash.calculateDeployAccountTransactionHash(
      v.contract_address,
      v.class_hash,
      v.constructor_calldata,
      v.salt,
      "0x1",
      v.max_fee,
      v.chain_id as constants.StarknetChainId,
      v.nonce
    );
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Deploy Account V3
  // -------------------------------------------------------------------------
  console.log("Deploy Account V3:");
  for (const v of fixture.vectors.deploy_account_v3) {
    const computed = hash.calculateDeployAccountTransactionHash({
      contractAddress: v.contract_address,
      classHash: v.class_hash,
      compiledConstructorCalldata: v.constructor_calldata,
      salt: v.salt,
      version: "0x3",
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
      nonceDataAvailabilityMode: v.nonce_da_mode,
      feeDataAvailabilityMode: v.fee_da_mode,
      resourceBounds: {
        l1_gas: gasBounds(v.l1_gas),
        l2_gas: gasBounds(v.l2_gas),
        l1_data_gas: gasBounds(v.l1_data_gas),
      },
      tip: v.tip,
      paymasterData: v.paymaster_data,
    });
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Declare V2
  // -------------------------------------------------------------------------
  console.log("Declare V2:");
  for (const v of fixture.vectors.declare_v2) {
    const computed = v2hash.calculateDeclareTransactionHash(
      v.class_hash,
      v.sender_address,
      "0x2",
      v.max_fee,
      v.chain_id as constants.StarknetChainId,
      v.nonce,
      v.compiled_class_hash
    );
    assertEqual(v.name, computed, v.expected_hash);
  }

  // -------------------------------------------------------------------------
  // Declare V3
  // -------------------------------------------------------------------------
  console.log("Declare V3:");
  for (const v of fixture.vectors.declare_v3) {
    const computed = hash.calculateDeclareTransactionHash({
      classHash: v.class_hash,
      compiledClassHash: v.compiled_class_hash,
      senderAddress: v.sender_address,
      version: "0x3",
      chainId: v.chain_id as constants.StarknetChainId,
      nonce: v.nonce,
      accountDeploymentData: v.account_deployment_data,
      nonceDataAvailabilityMode: v.nonce_da_mode,
      feeDataAvailabilityMode: v.fee_da_mode,
      resourceBounds: {
        l1_gas: gasBounds(v.l1_gas),
        l2_gas: gasBounds(v.l2_gas),
        l1_data_gas: gasBounds(v.l1_data_gas),
      },
      tip: v.tip,
      paymasterData: v.paymaster_data,
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
