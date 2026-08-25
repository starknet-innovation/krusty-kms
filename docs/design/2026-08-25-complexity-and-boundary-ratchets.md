# Complexity and boundary ratchets

## Goal

Reduce the highest-maintenance protocol and adapter paths without changing the
Tongo proof transcript or Cairo ABI. Prevent the same classes of complexity
from returning unnoticed.

## Transfer construction

Transfer now delegates to a private TransferBuildState. The state validates
immutable inputs once, then executes explicit phases: ciphertext preparation,
transcript construction, range proofs, the Fiat-Shamir proof, post-transfer
balance derivation, and optional auditing. Randomness is generated in the same
places and the transcript field order is unchanged. Existing transfer vectors
and protocol tests remain the behavior contract.

## Audit serialization

The common crate owns the typed Cairo Option<Audit> layout. Client and C FFI
convert their input models into AuditCalldata and do not manually append
balance, hint, and proof fields. This makes an ABI shape change a reviewed
change in one place. The new type is borrowed and contains no secret material.

## Test and CI boundaries

Client contract queries and wallet deployment detection expose narrow private
provider seams. Unit tests use deterministic mock providers to assert selector,
calldata, response parsing, and ContractNotFound behavior without a live node.

Guardrails now ratchet functions over 80 lines, deny Clippy cognitive-complexity
findings, and enforce line-coverage floors for the client crate, contract
adapter, and wallet adapter. The committed floors are deliberately current
baselines; each subsequent focused test should raise the applicable floor.
CI also compares committed coverage floors to the base revision, preventing a
coverage regression from being hidden by lowering or removing its floor.
The function ratchet lexically ignores braces in comments and strings, scans
all non-experimental Rust targets, and compares the PR head to source spans at
the base revision. Updating its committed baseline therefore cannot permit a
new or expanded oversized function.

## Failure modes

The function-span parser is a lightweight guardrail, not a Rust parser. It
errs on the side of blocking a new oversized function; maintainers can update
the baseline only with a design note and review. Coverage reporting requires
cargo-llvm-cov in CI. Local users may run the normal test suite when the tool
is unavailable.
