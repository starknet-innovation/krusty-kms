# OZ Multisig

Pinned Cairo package for a concrete OpenZeppelin `MultisigWallet` wrapper used
by `krusty-kms`.

Inputs:
- A Scarb toolchain capable of building Cairo `2.14.0` packages.
- OpenZeppelin governance dependency `openzeppelin_governance = "3.0.0"`.

Outputs:
- A locally reproducible Sierra artifact for `MultisigWallet`.
- Constructor calldata shape compatible with the Rust SDK:
  `[quorum, signers_len, signer_0, signer_1, ...]`.

Invariants:
- The upstream component is `openzeppelin_governance::multisig::MultisigComponent`.
- The wrapper exposes the upstream `IMultisig` ABI unchanged.
- Signer and quorum changes are self-administered and must go through the
  multisig transaction flow.
- The trusted coordination server is off-chain only; on-chain signer checks are
  performed by the multisig contract.

Build:

```bash
scarb build
```
