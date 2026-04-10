# OZ Account

Pinned Cairo package for the OpenZeppelin `AccountUpgradeable` preset used by
`krusty-kms`.

Inputs:
- A Scarb toolchain capable of building Cairo `2.14.0` packages.
- OpenZeppelin preset dependency `openzeppelin_presets = "3.0.0"`.

Outputs:
- A locally reproducible Sierra artifact for `AccountUpgradeable`.
- A checked-in manifest of the expected class hash per network/version in
  [`class-hashes.json`](./class-hashes.json).

Invariants:
- The canonical preset package is `openzeppelin_presets`.
- The canonical preset contract is `AccountUpgradeable`.
- The canonical constructor shape is `constructor(ref self: ContractState, public_key: felt252)`.
- Salt policy is not baked into the contract identity. Callers must choose it explicitly.
- The local Cairo source mirrors the upstream preset logic exactly so Scarb can
  emit a declareable contract artifact for this repo.

Build:

```bash
scarb build
```

Check or declare against a network:

```bash
./ensure_declared.sh --network sepolia
./ensure_declared.sh --network sepolia --declare
```
