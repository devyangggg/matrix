# Matrix RFC 001 — API contract

This is a specification package, not a running compute agent. Read `Matrix_RFC_001.md` for the design decisions, HLD, LLD, exact execution algorithm, failure assumptions, and 12-hour build plan.

## Files

- `main.tsp`: offline deployment types, signed wire records, and seven HTTP operations.
- `openapi.yaml`: generated OpenAPI 3.0 contract for implementing/inspecting the Python API.
- `package.json`, `package-lock.json`, `tspconfig.yaml`: pinned development-only TypeSpec build.
- `protocol_vectors.json`: reference workload fixtures, a canonical configuration hash vector, canonical JSON/hash vectors, an Ed25519-signed certified package, signed storage receipts, and negative cases with expected errors.
- `VERIFICATION.md`: checks actually completed while preparing this specification.

## Rebuild

Use Node.js 24 LTS (the preparation environment used 24.22.1) and npm:

```sh
npm ci --ignore-scripts
npm run build
```

The compiler writes `tsp-output/@typespec/openapi3/openapi.yaml`. The top-level `openapi.yaml` is the distribution copy. Node.js is not required on the Python compute peers.

## Runtime rules beyond the schema

Implement strict Pydantic models with unknown fields forbidden and strict integer validation. Reject duplicate JSON keys before model validation. Apply checks in the RFC order: byte cap, duplicate-key parse, schema including literal domains, identity hashes, membership and configuration, then signatures; the published negative vectors expect those codes. Enforce exact two-signer certificates, distinct signer IDs, signer order, and result-to-job parameter equality using RFC 001. The OpenAPI schema alone cannot enforce those cryptographic or cross-field invariants.

Index entries, health fields, and remote local-state fields are diagnostics; verify the embedded evidence yourself. A storage signature never counts as an execution signature. Expired storage receipts do not prove current durability.

## Test-vector scope

The zero configuration hash and fixed nonce are synthetic. Node A/B/C/D test private seeds are the publicly documented repeated bytes 0x01/0x02/0x03/0x04, respectively. These values exist solely for reproducible tests and must never become deployed keys. The protocol vectors do not constitute a trusted runtime membership configuration.

`trusted_configuration` is a separate fixture for canonical encoding and `config_hash` computation; it reuses the TEST keys but is not the configuration of the signed fixtures. `negative_vectors` state the expected error for each bad input. `signed_storage_receipts` are verifiable job and result receipts plus one expired example that must not count as durability.

Expected algorithm fixtures:

| Samples | Seed | Hits |
| ---: | ---: | ---: |
| 100,000 | 42 | 78,706 |
| 100,000 | 0 | 78,528 |

The actual four-host/tinc/Docker acceptance matrix remains implementation work. Compilation of this contract is not a claim that the distributed service has been built or tested.
