# Oracle Stdio JSONL V1

`krusty-kms-oracle` provides a newline-delimited JSON transport on top of the gateway surface.

## Transport Contract

- One JSON request per line on input
- One JSON response per non-empty input line on output
- Responses always use server protocol version `1.0`
- Malformed JSON returns `status = "error"` with `id = null`
- Malformed JSON uses the stable message `invalid request JSON`

## Supported Commands

- `get_protocol_info`
- `derive_account`
- `check_deployment`
- `deploy_account`
- `sign`
- `query_account_snapshot`
- `get_operation_status`

## Sign Contract

`sign` is now variant-specific rather than a generic `(key_domain, domain, payload)` bag:

- Stark sign results use `format = "stark_ecdsa"` and expose `public_key`, `signature_r`, and `signature_s`.
- Nostr sign results use `format = "nostr_bip340"` and expose `public_key` and `signature`.

Supported request variants:

- `kind = "stark_hash"`
  - `key_domain` is `StarknetAccount` or `TongoAccount`
  - `domain` is `TransactionHash` or `TypedDataHash`
  - `chain_id` and `hash` are required
- `kind = "stark_raw_message"`
  - `key_domain` is `StarknetAccount` or `TongoAccount`
  - `message` is a canonical felt hex string
- `kind = "nostr_event"`
  - `event_id` is a 32-byte lowercase hex string
- `kind = "nostr_raw_message"`
  - `payload` is `{ "Hex": "..." }` or `{ "Utf8": "..." }`

Impossible combinations are intentionally not representable on the wire. For example, there is no request shape that mixes a Nostr key with a Stark transaction hash.

## Request Shape

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-1",
  "command": "derive_account",
  "params": {
    "secret": "wallet-1",
    "key_domain": "StarknetAccount",
    "chain_id": "Sepolia",
    "path": {
      "coin_type": 9004,
      "account_index": 0,
      "address_index": 0
    },
    "account_class": {
      "kind": "OpenZeppelin",
      "class_hash": null,
      "source_label": null
    },
    "salt_policy": "PublicKey"
  }
}
```

## Successful Response Shape

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-1",
  "status": "ok",
  "result": {
    "kind": "derive_account",
    "value": {
      "operation": {
        "id": "derive-1",
        "kind": "DeriveAccount",
        "state": { "Accepted": { "tx_hash": null } },
        "provenance": { "...": "..." }
      },
      "value": { "...": "..." }
    }
  }
}
```

## Sign Request Example

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-sign",
  "command": "sign",
  "params": {
    "kind": "nostr_event",
    "secret": "nostr-secret",
    "derivation_path": {
      "coin_type": 1237,
      "account_index": 0,
      "address_index": 7
    },
    "event_id": "6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13"
  }
}
```

## Sign Response Example

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-sign",
  "status": "ok",
  "result": {
    "kind": "sign",
    "value": {
      "operation": {
        "id": "sign-1",
        "kind": "Sign",
        "state": { "Accepted": { "tx_hash": null } },
        "provenance": null
      },
      "value": {
        "format": "nostr_bip340",
        "public_key": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        "signature": "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
      }
    }
  }
}
```

## Stark Sign Example

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-sign-stark",
  "command": "sign",
  "params": {
    "kind": "stark_hash",
    "secret": "stark-secret",
    "key_domain": "StarknetAccount",
    "derivation_path": {
      "coin_type": 9004,
      "account_index": 0,
      "address_index": 3
    },
    "chain_id": "Sepolia",
    "domain": "TransactionHash",
    "hash": "0x0000000000000000000000000000000000000000000000000000000000001234"
  }
}
```

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-sign-stark",
  "status": "ok",
  "result": {
    "kind": "sign",
    "value": {
      "operation": {
        "id": "sign-stark-1",
        "kind": "Sign",
        "state": { "Accepted": { "tx_hash": null } },
        "provenance": {
          "chain_id": "Sepolia",
          "key_domain": "StarknetAccount",
          "derivation_path": {
            "coin_type": 9004,
            "account_index": 0,
            "address_index": 3
          },
          "class_hash": null
        }
      },
      "value": {
        "format": "stark_ecdsa",
        "public_key": "0x0000000000000000000000000000000000000000000000000000000000000456",
        "signature_r": "0x0000000000000000000000000000000000000000000000000000000000000111",
        "signature_s": "0x0000000000000000000000000000000000000000000000000000000000000222"
      }
    }
  }
}
```

## Compatibility Fixtures

The repository ships fixed JSON fixtures in `crates/oracle/tests/fixtures/` for:

- `get_protocol_info`
- `derive_account`
- `sign` with Nostr output
- `sign` with Stark output
- malformed JSON

Those fixtures are exercised by the golden test suite to keep the wire shape stable across refactors.

## Error Response Shape

```json
{
  "version": { "major": 1, "minor": 0 },
  "id": "req-1",
  "status": "error",
  "error": {
    "code": "InvalidRequest",
    "retryable": false,
    "message": "..."
  }
}
```

## Scope Boundary

V1 is intentionally request/response only. It does not yet provide:

- subscriptions
- multiplexed event streams
- socket transport
- keystore persistence policy
