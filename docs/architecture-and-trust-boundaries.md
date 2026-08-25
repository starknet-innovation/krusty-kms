# Architecture and trust boundaries

Krusty is a set of Rust libraries, language bindings, Cairo contracts, and a
small gateway runtime. This page records the security-relevant boundaries that
are easy to lose while making local changes.

## Layering

The dependency direction is deliberately one-way:

common feeds wallet-api, domain, crypto, and the adapter crates; crypto feeds
kms; kms feeds sdk; and sdk feeds client and WASM. The gateway may depend on
domain and common, but protocol and client code must not depend on the gateway.
The executable dependency check is the authority for the full list of allowed
edges.

The stable protocol boundary is the typed Cairo serialization in the common
crate. SDK operations create proofs and typed values. Client, C FFI, and WASM
adapters may parse caller data and present results, but must delegate exact
Cairo payload layout to that shared layer.

## Trust boundaries

| Boundary | Trusted responsibility | Untrusted or fallible input |
| --- | --- | --- |
| Local key material | SecretFelt redaction and zeroization; proof generation and signing stay local | Callers that provide private keys and password material |
| RPC provider | Request transport only | State, rates, class hashes, events, and every returned felt |
| Tongo calldata | Typed serialization preserves Cairo field order and option tags | Caller-provided JSON and FFI/WASM presentation data |
| C, WASM, and coordinator adapters | Parse, validate shape, and map errors | Foreign memory, browser inputs, network messages, and coordinator availability |
| Cairo account and multisig contracts | Enforce authorization and state transitions on chain | Off-chain proposal caches, signature delivery, and transaction ordering |

In particular, an RPC response is not proof of economic correctness. Consumers
must retain range and amount bounds when decrypting balances and must treat
remote values as checked inputs.

## Account upgrades and multisig

The OpenZeppelin account wrapper limits upgrades to self-calls. That protects
the entry point, but it does not make a new class hash safe: operators must
review and pin the replacement class before proposing an upgrade. An account
upgrade can change validation behavior, storage expectations, and signing
policy.

The OpenZeppelin multisig wrapper delegates signer membership, quorum,
confirmation, and execution to the upstream MultisigComponent. The on-chain
contract is the source of truth. The optional NATS or HTTP coordinator only
helps participants exchange signed notices; it must never be treated as a
quorum oracle or authorization source. Re-read proposal state before execute,
because a revocation, signer change, or upgrade may have landed after a local
cache entry was created.

## Transaction ordering and privacy limits

Transfer transcripts bind the chain id, Tongo address, sender address, nonce,
public keys, ciphertexts, and commitments. This prevents a proof from being
replayed into a differently bound protocol call. It does not reserve sequencer
ordering, provide encrypted mempool delivery, or protect a transaction from
being delayed, censored, front-run, or sandwiched.

Applications should obtain fresh nonce and state immediately before building a
transaction, expect stale-state rejections, and avoid treating a locally
generated proof as a guarantee of inclusion or execution order. Confidential
balances hide the protected values; surrounding call timing, sender identity,
contract address, and resulting transaction metadata can still be observable.
