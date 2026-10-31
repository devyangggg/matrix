# Specification verification

Prepared 31 October 2026 for RFC 001 revision 1.3. These checks concern the deliverable, not an implemented distributed service.

- TypeSpec compiler 1.17.0 (the pinned versions in `package.json`) compiled `main.tsp` with no errors and no warnings. The package was installed with Bun because npm was unavailable in the preparation environment; the emitted contract is the compiler's output, not a hand edit.
- Generated OpenAPI is version 3.0.0, API version 1.0.0, and lists all seven core operations.
- Error responses are per operation: `GET /v1/health` and `GET /v1/jobs` return 500/503; `PUT /v1/jobs/{job_id}` has no 404; reads have no 409 or 413; every operation can return 500 `INTERNAL_ERROR`.
- `ErrorCode` contains `INTERNAL_ERROR` and `UNKNOWN_ARTIFACT`.
- `MonteCarloResult.hits` has `minimum: 0`; `schema_version` is an integer with minimum and maximum 1.
- `PeerConfiguration.vpn_ip` and `.api_url` carry the patterns from RFC 001 section 4.2.
- `Health.running` and `.queued` are bounded 0..1, `JobIndex.jobs` is a bounded array of job IDs, and `Ingested` carries only `stored: true`; the unused `JobIndexEntry` model and `certified_hint` field are removed.
- The revision 1.3 timer budget is arithmetically consistent: one waiting execution gives a 240 s worst wait inside the 300 s collection budget, and the file profile adds one 60 s fetch and uses 360 s.
- The emitted execution-certificate schema requires exactly two attestations; distinctness, matching bindings, ordering, and signatures remain runtime checks.
- Canonical JSON and SHA-256 in `protocol_vectors.json` were recomputed: both workload fixtures, the job spec and job ID, and the trusted configuration fixture (canonical bytes and `config_hash`) all matched.
- Ed25519 signatures verified against the published public keys: the signed job, both execution attestations, the job storage receipt, and the result storage receipt. The certificate's signers are distinct and sorted.
- Negative vectors reject for the stated reason: duplicate object key, boolean as integer, unknown property, altered signed parameter, wrong domain, and a valid signature from a non-member key.
- The expired receipt example is outside its signed deadline and must not be counted as durability.
- Sample signed job, result, and certificate-package sizes fit the RFC body limits.
- The two workload fixtures were calculated from the RFC integer reference algorithm.
- RFC sections, cross-references, and code fences were checked for completeness and balance.

Not performed: implementation of the Python agent, FastAPI conformance tests, Docker execution, tinc installation, physical-machine determinism tests, fault injection, partitions, recovery, performance measurements, or a production security review. Those remain the implementation acceptance gates in the RFC.
