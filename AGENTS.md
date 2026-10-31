# AGENTS.md — building Matrix

Read this before you write any code in this repository.

Matrix is a Byzantine-tolerant release gate for Go binaries. 8 builders each build a tagged commit, and a release is certified when 3 of them signed the same hash. It is a 12-hour hackathon MVP. **Keep it simple.** The smallest code that meets the spec wins.

## 1. Documents, in priority order

| Doc | Use it for |
|---|---|
| [Matrix_RFC_001.md](Matrix_RFC_001.md) | **The spec.** Protocol, parameters, security rules, exit codes. Wins every conflict. |
| [docs/LLD.md](docs/LLD.md) | Function signatures, module contracts, file formats, tests. Your build plan. |
| [docs/openapi.yaml](docs/openapi.yaml) | The exact HTTP contract (routes, bodies, status codes). |
| [docs/HLD.md](docs/HLD.md) | The big picture: components, layering, flows, trust boundaries. |

If two documents disagree, follow the RFC, then **stop and report the conflict** in your final message. Do not silently pick one. If something is unspecified, choose the simplest option, add a row to LLD §10, and say so.

## 2. KISS rules

1. **No new dependencies.** Runtime: `pynacl`, `aiohttp`, `textual`. Dev: `pytest`, `pytest-asyncio`. Use the standard library for everything else (`sqlite3`, `tomllib`, `hashlib`, `json`, `argparse`, `logging`, `asyncio`).
2. **No frameworks or layers that the LLD does not name.** No ORM, no FastAPI, no pydantic, no DI container, no plugin system, no config files beyond genesis.
3. Plain functions and frozen dataclasses. Use a class only when it holds state (`Store`, `Engine`, `PeerClient`, `Fault`).
4. One module per file listed in LLD §1. Do not add modules without a reason you can state in one sentence.
5. No speculative features: no flags, options, retries, caches or abstractions that the spec does not ask for. Nothing from RFC §10 (future work).
6. Prefer explicit over clever. Repetition of three lines beats an abstraction.
7. Short functions, early returns, no deep nesting. Comments explain *why*, not *what*.

## 3. Invariants you must never break

These are the security of the system. A change that weakens one is wrong even if the tests pass.

1. **Parsers and `verdict()` never raise** on any input. Hostile input → `None` / ignored.
2. **Canonical JSON** (`canon.canonical_json`) for every hash and signature. No floats in signed data. Duplicate JSON keys are rejected.
3. **Domain-separated signatures:** `b"matrix/v1\0" + genesis_hash + b"\0" + canonical_json(...)`. Never sign or verify raw bodies.
4. **`verdict()` gets its request from the caller**, never from a bundle or peer. `verify` checks the request signature *and* expected repo/tag (/commit).
5. **Count only** non-equivocating, selected, validly-signed attestations for this exact `request_id`. Threshold is `f+1` from genesis.
6. **`FAILED` is a vote only for a deterministic, rerun-confirmed compile error** (LLD §3.8). Every environmental problem is `ERROR` and **abstains**. `BAD_REF` and `BAD_RECIPE` abstain.
7. **Persist before broadcast.** Commit the own attestation to SQLite, then send it. Never sign two different results for one request (except the `equivocate` demo fault).
8. **Subprocesses use argument lists** (`create_subprocess_exec`). Never `shell=True`, never string-built commands.
9. **Build sandbox flags are not optional:** pinned image digest from genesis, `--platform linux/amd64`, `--user uid:gid`, `--cap-drop ALL`, `no-new-privileges`, resource limits, `--network none` for the build step, read-only source and module mounts, `GOTOOLCHAIN=local`, `GOPROXY=https://proxy.golang.org` (no `direct`), ldflags allowlist.
10. **Never join user input onto a filesystem path.** Validate IDs and hashes with `re.fullmatch(..., re.ASCII)` first; look artifacts up in the DB.
11. **Fail closed.** Only exit code 0 means success (RFC §6.4).
12. Fault modes are inert unless the node was started with `--allow-faults`.

## 4. Repository layout

```
Matrix_RFC_001.md          spec
docs/HLD.md docs/LLD.md docs/openapi.yaml
matrix/                    the package (LLD §1, §3)
tests/                     unit tests; tests/integration/ needs Docker + network
scripts/dev_genesis.py     dev keys + genesis (LLD §12.1)
examples/faults/           backdoor.patch for the inject demo
genesis.json genesis.demo.json   real network (tinc demo)
Dockerfile docker-compose.yml docker-compose.faults.yml .env.example
```

Imports only point downward (HLD §4): `canon, crypto, genesis` → `model, select, verdict` → `store, builder` → `protocol, net, faults` → `node, cli, tui`. The pure layers (bottom two) must not import `asyncio`, `aiohttp`, `sqlite3` or `subprocess`.

## 5. Environment

- Linux, or **WSL2 on Windows**. The repo is on a Windows machine, but builders need Linux process groups, `os.getuid()` and the Docker socket. Run Python, tests and Docker from WSL2.
- Python 3.11+, Docker, git.

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q                       # unit tests: fast, no Docker, no network
pytest -q -m integration        # 8 local builders + real Docker builds
```

## 6. Build order

Follow RFC §9.3. Each step must pass its tests before the next one starts.

| # | Module(s) | Done when |
|---|---|---|
| 1 | `pyproject.toml`, `canon`, `crypto`, `genesis`, `model` | `test_canon`, `test_crypto`, `test_genesis`, `test_model` pass |
| 2 | `select`, `verdict` | `test_select`, `test_verdict`, `test_verdict_modelcheck`, `test_fuzz` pass |
| 3 | `scripts/dev_genesis.py` | Generates a genesis that `load_genesis` accepts |
| 4 | `store`, `builder` | `test_builder_classify` passes; one real build of the sample repo gives the same hash twice |
| 5 | `protocol`, `faults` | `test_protocol` passes with a fake builder and fake peers |
| 6 | `net`, `node` | 8 local nodes start; `curl /v1/health` works; routes match `openapi.yaml` |
| 7 | `cli` (`keygen`, `release`, `status`, `verify`, `evidence`) | `test_verify` passes; end-to-end certify on compose |
| 8 | `tui` | Shows builders, releases, detail and evidence from a live network |
| 9 | Integration fault matrix | RFC §9.1 integration cases pass |

**Never cut** (RFC §9.4): signatures, signed requests, strict parsing, `verdict` + model check, builder hardening and outcome classification, selection, certificate verification, exit codes. If time runs out, cut in the RFC §9.4 order.

## 7. Testing rules

- Every module ships with its tests in the same change. Test the pure layers with plain values: no network, no Docker, no sleeps.
- Inject time (`clock=`) and side effects (fake `build`, fake `PeerClient`) instead of patching globals.
- The verdict model check (RFC §9.1) must pass at all times. If you change `verdict.py`, `model.py` or `select.py`, run it.
- Add a regression test for every bug you fix.
- Do not mark a task done while any test fails. Report failures verbatim.

## 8. Run it (single machine)

```bash
cp .env.example .env                         # set MATRIX_DATA (absolute), UIDs, DOCKER_GID
mkdir -p "$MATRIX_DATA" dist
docker buildx imagetools inspect golang:1.23 # copy the linux/amd64 digest
python scripts/dev_genesis.py --out dev --addrs compose --profile demo \
  --repo https://github.com/<org>/<repo> --image golang@sha256:<digest>
docker pull --platform linux/amd64 golang@sha256:<digest>
docker compose up -d --build
docker compose run --rm cli release --repo https://github.com/<org>/<repo> \
  --tag v1.2.0 --commit <sha> --key /etc/matrix/keys/release.key --wait 600 --out dist/
docker compose run --rm cli tui
```

Without Docker Compose: `python scripts/dev_genesis.py --addrs local ...` and start 8 `matrix-node` processes on `127.0.0.1:7700–7707`.

Demo faults: edit [docker-compose.faults.yml](docker-compose.faults.yml), then `docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builderN`. Never more than 2 malicious builders at once.

## 9. Don'ts

- Don't reintroduce commit-reveal, anonymous requests or recipes inside requests. Those were rev 2/3; rev 4 removed them.
- Don't let a builder auto-exclude peers, or change selection based on evidence.
- Don't read the request from a bundle or certificate without verifying it against the caller's expectations.
- Don't treat a timeout, OOM, Docker error, network error or `go mod download` failure as `FAILED`.
- Don't add HTTP authentication, TLS or a web dashboard. Transport is untrusted by design; signatures carry the security.
- Don't commit keys, `.env`, `dev/`, `data/` or `dist/` (see `.gitignore`).
- Don't edit the RFC to match your code. If the RFC is wrong, report it.

## 10. When you finish a task

Report: what you changed (files), which tests you ran and their result, any spec conflict or LLD §10 decision you added, and anything you skipped.
