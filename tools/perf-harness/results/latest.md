# KMS Perf Report

- generated_at_unix: 1771065040
- git_commit: `unknown`
- samples: 3
- warmup: 1

| Case | Rust median (ms) | Zig median (ms) | Zig/Rust | Rust p95 | Zig p95 | Status |
|---|---:|---:|---:|---:|---:|---|
| mnemonic_to_seed | 6.481 | 56.234 | 8.677 | 6.484 | 56.617 | ok |
| derive_keypair | 6.454 | 62.448 | 9.675 | 6.487 | 62.499 | ok |
| pedersen_hash | 6.538 | 44.132 | 6.750 | 6.554 | 44.166 | ok |
| poseidon_hash_many | 6.506 | 43.676 | 6.713 | 6.532 | 44.130 | ok |
| curve_mul_generator | 5.580 | 44.078 | 7.899 | 6.443 | 44.090 | ok |
| poe_prove_verify | 6.460 | 56.226 | 8.704 | 6.461 | 56.295 | ok |
| elgamal_prove_verify_decrypt | 6.452 | 87.156 | 13.509 | 6.548 | 87.501 | ok |
| range_prove_verify | 6.519 | 230.078 | 35.292 | 6.548 | 233.955 | ok |
| audit_prove_verify | 6.431 | 93.732 | 14.575 | 6.434 | 94.183 | ok |
| tongo_fund | 6.496 | 49.784 | 7.663 | 6.516 | 55.357 | ok |
| tongo_transfer | 6.521 | 470.800 | 72.193 | 6.533 | 475.324 | ok |
| tongo_rollover | 6.436 | 49.564 | 7.702 | 6.496 | 53.130 | ok |
| tongo_withdraw | 6.451 | 249.740 | 38.714 | 6.482 | 255.440 | ok |
| tongo_ragequit | 6.435 | 56.608 | 8.796 | 6.460 | 56.645 | ok |
