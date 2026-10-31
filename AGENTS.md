# AGENTS.md — building Matrix

Read this before you write any code in this repository. It applies to every human and every coding agent on the team.

Matrix is a Byzantine-tolerant release gate for Go binaries. n builders each build a tagged commit, and a release is certified when f+1 of them signed the same hash. The demo (RFC rev 5) is 4 laptops on a phone hotspot, one builder each: n = 4, f = 1, threshold 2; the laptops found the network with `matrix up` and discover each other's addresses. It is a 12-hour hackathon MVP built by **4 people, each driving coding agents on a separate track**. **Keep it simple.** The smallest code that meets the spec wins.

## 0. Start here

1. Find your track in §3 and your next task in §6. Work only on that task.
2. Touch only files your track owns (§3.2). Need a change elsewhere? See §7.4.
3. Code against the frozen contracts (§5), not against another track's half-finished code. Use the fakes in `tests/fakes.py` until the real module lands.
4. Finish with the PR checklist (§9) and the report format (§12).

## 1. Documents, in priority order

| Doc | Use it for | Status |
|---|---|---|
| [Matrix_RFC_001.md](Matrix_RFC_001.md) | **The spec (rev 5).** Protocol, parameters, founding ceremony, discovery, security rules, exit codes. Wins every conflict. | Done (rev 5) |
| [docs/LLD.md](docs/LLD.md) | Function signatures, module contracts, file formats, tests. **The frozen contract (§5).** | Done |
| [docs/openapi.yaml](docs/openapi.yaml) | The exact HTTP contract. | Done |
| [docs/HLD.md](docs/HLD.md) | Components, layering, flows, trust boundaries. | Done |
| `AGENTS.md` (this file) | Team, ownership, tasks, workflow, quality gates. | Done |
| [docs/OPS.md](docs/OPS.md) | Per-laptop setup: WSL2 mirrored networking, firewall (UDP 7788, TCP 7700), Docker, pre-pull, phone hotspot, `matrix up`, publishing the genesis pin, troubleshooting. tinc/WireGuard optional. | Rev 5 rewrite |
| [docs/DEMO.md](docs/DEMO.md) | Demo runbook: the 7 scenes from RFC §9.2 (rev 5), exact commands, expected output, reset steps, fallbacks. | Rev 5 rewrite |
| `examples/ci/` | Publisher and consumer CI examples (RFC §7.11). | **To write: task D5** |

If two documents disagree, follow the RFC, then **stop and report the conflict** (§12). Do not silently pick one. If something is unspecified, choose the simplest option, add a row to LLD §10 in the same PR, and say so in the PR.

## 2. Gaps closed by this file

To let agents work in parallel, we needed decisions the RFC, HLD and LLD did not make. This file makes them:

| Gap | Resolved in |
|---|---|
| Who owns which module and file; how to avoid merge conflicts | §3 |
| Decisions only humans can make (org, repo, image digest, laptops, keys) | §4 |
| When interfaces freeze; how to change one; how to work before a dependency lands | §5 |
| Shared test fixtures, deterministic test keys, golden vectors that all tracks agree on | §5.3 |
| Exact `pyproject.toml`, tooling, lint and format rules | §8 |
| A task backlog with IDs, dependencies and acceptance tests | §6 (rev 5 tasks: §6.1) |
| Git branching, PR, review and merge rules for 4 people plus agents | §7 |
| CI quality gates | §8.3 |
| The sample Go repository used for builds and the demo | §10 |
| Sync checkpoints over the 12 hours | §11 |
| How an agent receives a task and reports back | §12 |
| Missing docs (ops runbook, demo runbook, CI examples) | §1, tasks C1 and D5 |

## 3. Team and ownership

### 3.1 Tracks

| Track | Person | Mission | Modules |
|---|---|---|---|
| **A: Core and protocol** | `TBD-A` | Pure core, verdict and the protocol engine. Owns the shared test kit. | `canon`, `crypto`, `genesis`, `model`, `select`, `verdict`, `protocol` |
| **B: Build and storage** | `TBD-B` | Reproducible hardened builds, SQLite store, sample Go repo, image pin. | `builder`, `store` |
| **C: Network and ops** | `TBD-C` | HTTP server and peer client, address discovery, node entrypoint, faults, hotspot setup (tinc optional), compose, `network.toml`, genesis files, integration harness. | `net`, `discovery`, `node`, `faults` |
| **D: Clients and demo** | `TBD-D` | `matrix` CLI (including the `matrix up` founding ceremony), TUI, certificate flow, demo runbook, CI examples. | `cli`, `tui` |

### 3.2 File ownership

Only the owner (or the owner's agents) edits these files. Anyone may **read** everything.

| Owner | Files |
|---|---|
| A | `pyproject.toml`, `matrix/__init__.py`, `matrix/{canon,crypto,genesis,model,select,verdict,protocol}.py`, `tests/conftest.py`, `tests/fakes.py`, `tests/vectors/`, `tests/test_{canon,crypto,genesis,model,select,verdict,verdict_modelcheck,fuzz,protocol}.py`, `.github/workflows/ci.yml` |
| B | `matrix/{builder,store}.py`, `tests/test_{builder_classify,store}.py`, `tests/integration/test_builder.py`, `Dockerfile`, `examples/faults/backdoor.patch`, the sample repo (§10) |
| C | `matrix/{net,discovery,node,faults}.py`, `tests/test_{net,discovery,faults}.py`, `tests/integration/{harness.py,test_matrix.py}`, `scripts/`, `docker-compose*.yml`, `.env.example`, `network.toml`, `genesis.json`, `genesis.demo.json`, `docs/OPS.md` |
| D | `matrix/{cli,tui}.py`, `tests/test_{cli,verify,tui}.py`, `docs/DEMO.md`, `examples/ci/` |
| Shared (any track, small appended edits only) | `docs/LLD.md` §10 rows, `.gitignore`, this file's §4 table |
| Humans only | `Matrix_RFC_001.md`, §3–§7 of this file |

## 4. Human decisions (blocking, hour 0)

Agents must not guess these. Fill the table in the first 30 minutes and commit it. Until a value is filled, agents use the placeholder and must not hard-code a real value elsewhere.

| # | Decision | Owner | Value |
|---|---|---|---|
| H1 | Names for `TBD-A..D` | all | TBD |
| H2 | GitHub org that hosts the sample repo | B | TBD (placeholder `<org>`) |
| H3 | Sample repo URL (§10) | B | `https://github.com/<org>/matrix-hello` |
| H4 | Go toolchain image: `golang:1.23`, pinned `linux/amd64` digest | B | `golang@sha256:TBD` |
| H5 | Measured `build_timeout_s` (one build at a time per laptop, RFC §9.1) | B | TBD (default 150 full / 45 demo) |
| H6 | Laptops and builders | C | 4 laptops, one builder each (n = 4, f = 1). Builder id = operator = the laptop's hostname via `matrix up` (or `--name`). Addresses discovered by signed hellos; no fixed IPs. Laptop A is also the publisher (HLD §5.1) |
| H7 | Venue network plan and fallback | C | Phone hotspot, plain LAN (UDP 7788, TCP 7700). tinc / WireGuard optional, for privacy only. Fallback: another phone or a travel router |
| H8 | Release-signer keys | D | Every founder holds its own release key, `~/.matrix/keys/release.key` (genesis id `<name>-rel`), generated locally by `matrix up` and never copied |
| H9 | Machine used for offline `matrix verify` in the demo | D | Any laptop with Wi-Fi off, or a judge's machine |

## 5. Contracts and parallel work

### 5.1 The freeze

- **Hour 1: contracts freeze.** The public signatures in LLD §3, the HTTP contract in `openapi.yaml`, the SQLite schema (RFC §7.8) and the data formats (LLD §4) are frozen.
- After the freeze, changing a contract needs one PR that updates the LLD (or `openapi.yaml`), the implementation **and every caller**, approved by the owners of all affected tracks. Prefer adding a new function over changing an existing one.
- Internals (private helpers, names starting with `_`) are free to change.

### 5.2 Cross-track contracts

| Provider → consumer | Contract | Fake until it lands |
|---|---|---|
| A `genesis`, `model`, `crypto` → everyone | LLD §3.2–§3.4 | none needed: lands first (A2, A3) |
| A `verdict` → A `protocol`, D `cli`/`tui` | LLD §3.6 | `tests/fakes.py: fixed_verdict(...)` |
| B `builder.build` → A `protocol` | `async build(req, rid, g, env, attempt, patch) -> Outcome` | `fakes.FakeBuilder(outcomes=[...])` |
| B `Store` → A `protocol`, C `net` | LLD §3.7 | `Store(":memory:")` once B2 lands; before that `fakes.FakeStore` |
| A `Engine` → C `net`, C `node` | `on_request`/`on_attest` return `(status, json_body)`; `build_worker`, `sync_loop`, `recover` | `fakes.FakeEngine` (records calls, returns 202) |
| C `PeerClient` → A `protocol`, D `cli`/`tui` | LLD §3.10 | `fakes.FakePeers` (in-memory dict of node → responses) |
| C HTTP API → D `cli`/`tui` | `openapi.yaml` | `aiohttp` test server in the test that serves fixture JSON |
| C `Fault` → A `protocol`, C `net` | LLD §3.11 | `Fault()` (no mode) |

### 5.3 Shared test kit (task A1, hour 0–1)

Everything here is deterministic, so tests from all tracks agree byte for byte.

- `tests/conftest.py` fixtures: `genesis` (8 nodes, laptopA..D, f=2, demo profile, repo `https://github.com/org/hello`, image `golang@sha256:` + 64 `a`s), `keys` (dict id → `SigningKey`), `release_env` (signed request for `v1.2.0`, commit `"1"*40`), `attest(signer, result)` factory, `clock` (manually advanced).
- Test key seeds: `sha256(b"matrix-test:" + id.encode())`. Never use these keys outside tests.
- `tests/vectors/`: `canonical.json` (inputs → canonical bytes), `request.json` (request body → `request_id`), `envelope.json` (unsigned dict + seed + genesis hash → signed bytes hex → signature). Ed25519 is deterministic, so signatures are fixed. A's tests generate and assert them; any track may read them.
- `tests/fakes.py`: the fakes listed in §5.2. Only A edits it; others ask (§7.4).

## 6. Task backlog

Pick the lowest-numbered task in your track whose dependencies have merged. "Accept" lists what must pass before the PR merges. Hours are targets from RFC §9.3.

The track tables below are the original plan. RFC rev 5 (4 laptops, one builder each, `matrix up`, discovered addresses) adds tasks R1–R7 (§6.1) and supersedes C1's tinc requirement, C7 and X1–X2; those rows are marked.

### Track A: Core and protocol

| ID | Task | Depends | Accept | Hours |
|---|---|---|---|---|
| A1 | `pyproject.toml` (§8.1), package skeleton with every module from LLD §1 as stubs (`raise NotImplementedError`), `tests/conftest.py`, `tests/fakes.py`, CI workflow (§8.3) | — | `pip install -e ".[dev]"`; `pytest` runs; CI green | 0–0.5 |
| A2 | `canon`, `crypto`, golden vectors | A1 | `test_canon`, `test_crypto` incl. replay rejection | 0.5–1 |
| A3 | `genesis`, `model` (request, recipe, ldflags, envelope, certificate) | A2 | `test_genesis`, `test_model` | 1–2.5 |
| A4 | `select`, `verdict`, model check, fuzz | A3 | `test_select`, `test_verdict`, `test_verdict_modelcheck` (< 30 s), `test_fuzz` | 2.5–4 |
| A5 | `protocol.Engine`: `on_request`, `on_attest`, admission, worker, attest (persist then broadcast) | A4, B2 (or FakeStore) | `test_protocol`: extra requests queued in SQLite, never shed (LLD L30/L31), persist-before-broadcast, idempotent submit, 409 unknown/expired | 4–6 |
| A6 | `sync_loop`, `recover`, `detect_evidence`, `is_settled` | A5 | `test_protocol`: restart re-sends without rebuild, EQUIVOCATION / DISAGREE / STALL, settled skip | 6–8 |
| A7 | Support the integration fault matrix; fix protocol bugs found by C6 | C6 | RFC §9.1 integration rows pass | 8–10 |

### Track B: Build and storage

| ID | Task | Depends | Accept | Hours |
|---|---|---|---|---|
| B1 | Pin the Go image (H4), pre-pull on all laptops, build the sample repo on every laptop, record hash and time (H5) | B1s | Same hash on all 4 laptops; timings in the PR | 0–1 |
| B1s | Create the sample repo (§10) with all tags; write `examples/faults/backdoor.patch`; record the honest and backdoored hashes in §10 | — | Tags pushed; hashes recorded | 0–1 |
| B2 | `store.py` (LLD §3.7) | A1 | `test_store` on `:memory:` and a temp file; `record_own_attestation` is one transaction | 1–2.5 |
| B3 | `builder.py` steps 0–4, `docker_common`, `classify_go_build`, BAD_REF markers | A3 | `test_builder_classify`; `tests/integration/test_builder.py`: honest hash = B1 hash, broken tag → FAILED, missing recipe → BAD_RECIPE, wrong tag → BAD_REF | 2.5–5.5 |
| B4 | Timeout kill (process group + `docker kill`), `cleanup_startup`, `expire_artifacts`, disk check, log cap | B3 | Integration: a 1 s timeout leaves no container and no `work/` dir | 5.5–7 |
| B5 | `Dockerfile` working with compose; hardening review of every docker flag against §13.2 rule 9 | B4, C4 | `docker compose up` builds the sample repo inside compose | 7–9 |

### Track C: Network and ops

| ID | Task | Depends | Accept | Hours |
|---|---|---|---|---|
| C1 | Laptop network (H7) and `docs/OPS.md`. Rev 5: phone hotspot, plain LAN; tinc optional, not required | H6, H7 | All laptops ping each other on the hotspot; UDP 7788 and TCP 7700 open | 0–2 |
| C2 | `scripts/dev_genesis.py` (LLD §12.1) | A3 | Output loads with `load_genesis`; `--addrs local` and `compose` both work | 1–2 |
| C3 | `net.py`: all routes from `openapi.yaml`, body limits, error codes, `PeerClient` | A1 (FakeEngine) | `test_net` with `aiohttp` test client: every route, every status code in `openapi.yaml` | 2–5 |
| C4 | `node.py`: flags, startup checks, wiring, signal handling | C3, A5 | 8 nodes start locally; `curl /v1/health` on each | 5–6 |
| C5 | `faults.py` + `docker-compose.faults.yml` scenes | C4 | `test_faults`; refusing fault flags without `--allow-faults` | 6–7.5 |
| C6 | `tests/integration/harness.py` (start/stop 8 local nodes with a temp data dir each) and `test_matrix.py` (RFC §9.1 fault matrix) | C5, B4, A6 | Fault matrix passes on one machine | 7.5–10 |
| C7 | **Superseded by R4 (rev 5).** Genesis comes from the `matrix up` ceremony on every laptop, not hand-assembled. C still publishes the resulting genesis hash and `genesis.json` for consumers in `docs/OPS.md` | R4 | The published hash equals `~/.matrix/genesis.sha256` on every laptop | 8–9 |

### Track D: Clients and demo

| ID | Task | Depends | Accept | Hours |
|---|---|---|---|---|
| D1 | `cli` skeleton (`argparse`, exit codes), `keygen`, `verify` (offline) | A4 | `test_verify`: every RFC §6.4 verify row and every LLD §11 case | 1–4 |
| D2 | `release` (sign, submit until f+1 distinct operators accepted, poll, union, artifact download, certificate), `status`, `evidence` | D1, C3 (or a test server) | `test_cli` against an `aiohttp` test server: CERTIFIED, BUILD_FAILED, NOT_REPRODUCIBLE, PENDING timeout, corrupted artifact skipped | 4–6.5 |
| D3 | `tui.py`: Builders and Releases screens | D2 | Manual: shows a live compose network | 6–8 |
| D4 | TUI Detail and Evidence screens | D3 | Manual: equivocation proof visible | 8–9.5 |
| D5 | `docs/DEMO.md` (7 scenes of RFC rev 5 §9.2, commands, expected output, reset, fallbacks) and `examples/ci/{publisher,consumer}.yml` | D2, B1s | A dry run of the demo following only `DEMO.md` | 9–10.5 |

### All tracks

| ID | Task | Hours |
|---|---|---|
| X1 | **Superseded by R7.** End-to-end over the hotspot: certify, upload, verify on the offline machine | 10–11.5 |
| X2 | **Superseded by R7.** Rehearse the demo twice following only `DEMO.md` | 11.5–12 |

Cut order if behind: RFC §9.4. **Never cut** the items listed there.

### 6.1 Rev 5 backlog (4 laptops, `matrix up`, discovery)

Spec: RFC rev 5 (founding ceremony, address discovery, demo), HLD §5.1 and §6.1–§6.2. Owner track in brackets. Static membership, the security core and every §13.2 invariant are unchanged.

**Status (branch `roovy-4`):** R1–R6 implemented with unit tests. The integration fault matrix (R6) is written and collects, but has not run yet: it needs Docker, the pinned image and the pushed sample repo. R7 is open.

| ID | Task | Depends | Accept |
|---|---|---|---|
| R1 | [C] `matrix/discovery.py`: hello build / parse / verify (≤ 512 bytes, strict keys, signer in genesis, our genesis hash, `seq` strictly increasing, signature last), in-memory address book, UDP announcer and listener on 7788 (every 5 s, at start, on address change, unicast reply to a new or changed member), online window 15 s. Standard library only | A3 | `test_discovery`: valid hello accepted; stranger, forged, replayed, oversized and wrong-genesis hellos dropped without raising; online/offline by `last_seen` |
| R2 | [C] `net.py`: `PeerClient` resolves addresses from the address book, else genesis `addr`, else unreachable; `GET /v1/peers`; `GET /v1/requests/{id}/log` loopback only (404 otherwise) | R1 | `test_net`: `/v1/peers` shape per `openapi.yaml`; log 404 for a non-loopback caller; address book wins over genesis `addr` |
| R3 | [A] `genesis.py`: `addr` optional. [C] `node.py`: discovery task, `--advertise HOST:PORT`, `--no-discovery` (for the local harness) | R1 | `test_genesis`: genesis without `addr` loads, all other parse rules unchanged; the node starts with and without discovery |
| R4 | [D] `cli.py`: `matrix up` (local keys under `~/.matrix/keys/`, `network.toml`, founder and endorse messages, seal checks, deterministic genesis, short code, unanimous endorsement, 5 min abort, `--refound`, fault flag pass-through, then start the node); address resolution via `/v1/peers` with every hello re-verified; default paths under `~/.matrix/` | R1, R2, R3 | `test_cli` with fake sockets: 4 founders give byte-identical genesis and short code; seal refused below 4 founders, duplicate ids or a `params_hash` mismatch; missing endorsement aborts and writes nothing; rogue founder only changes the short code |
| R5 | [D] `tui.py`: Builders screen shows address, online/offline, last seen and genesis match from the local node's `/v1/peers`; log tail only for the local builder | R2 | Manual: 4 builders online on the hotspot; a laptop with Wi-Fi off turns offline in ~15 s |
| R6 | [C] `network.toml`; `scripts/dev_genesis.py --nodes 4`; compose for n = 4 needs no new file: with a `--nodes 4` dev genesis start only `builder1..4` (the existing fault overrides on builder3 and builder2 apply); integration fault matrix for f = 1 | R3 | Integration: one faulty builder never certifies a wrong hash; 1 faulty + 1 offline certifies; 3 offline stays `PENDING` |
| R7 | [all] 4-laptop end-to-end over the hotspot, then two rehearsals following only `DEMO.md` | R1–R6, D5 | All 7 demo scenes (§10) pass twice |

## 7. Git workflow

### 7.1 Branches and worktrees

- `main` is always green. Nobody pushes to it directly.
- Branch per task: `<track>/<task-id>-<slug>`, for example `a/A4-verdict`, `b/B3-builder`.
- Each person runs their agents in a separate git worktree (`git worktree add ../matrix-a a/A4-verdict`). Two agents never share a working tree.
- Rebase on `main` before opening a PR and again before merging. Never force-push someone else's branch.

### 7.2 Commits and PRs

- Commit message: `<task-id>: <imperative summary>`, for example `A4: add verdict model check`.
- One task per PR. Keep PRs under ~400 changed lines; split otherwise.
- PR description: the task ID, what changed, tests run with results, any LLD §10 row added, anything skipped.
- Squash-merge.

### 7.3 Review

- Every PR needs CI green and one human approval. The reviewer is from another track when the PR touches a contract (§5.2), otherwise any teammate.
- A PR that touches anything in §13 (invariants) needs approval from Track A's owner.

### 7.4 Needing a change in someone else's file

Do not edit it. Open a short issue (or message) to the owner with: the file, the exact change, and why. Meanwhile keep working against a fake or a local shim in your own test files. If the owner is blocked for more than 30 minutes, agree on a hand-over in chat and note it in the PR.

### 7.5 Merge order hot spots

`pyproject.toml` (A), `tests/fakes.py` (A), `docs/LLD.md` §10 (shared, append only). Merge these early and small.

## 8. Tooling

### 8.1 `pyproject.toml` (task A1, exact content)

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "matrix"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["pynacl>=1.5", "aiohttp>=3.9", "textual>=0.60"]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23", "ruff>=0.5"]

[project.scripts]
matrix-node = "matrix.node:main"
matrix = "matrix.cli:main"

[tool.setuptools]
packages = ["matrix"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
markers = ["integration: needs Docker and network"]
addopts = "-m 'not integration'"

[tool.ruff]
line-length = 100
target-version = "py311"
```

### 8.2 Environment

- Linux, or **WSL2 on Windows**. Builders need Linux process groups, `os.getuid()` and the Docker socket. Run Python, tests and Docker from WSL2, not PowerShell.
- Python 3.11+, Docker, git.

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
pytest -q                       # unit tests: fast, no Docker, no network
pytest -q -m integration        # needs Docker + network (B3, B4, C6)
```

### 8.3 CI (`.github/workflows/ci.yml`, task A1)

On every PR and on `main`: Ubuntu, Python 3.11, `pip install -e ".[dev]"`, `ruff check .`, `ruff format --check .`, `pytest -q`. Integration tests are **not** in CI (they need Docker and GitHub access); the PR author runs them and pastes the result.

## 9. Definition of done (PR checklist)

- [ ] Implements exactly the task; no extra features (§13 KISS).
- [ ] Matches the LLD signatures and `openapi.yaml`; no contract change, or one approved per §5.1.
- [ ] Tests added in the same PR; `ruff` and `pytest -q` pass locally and in CI.
- [ ] Integration tests run and pasted, if the task touches `builder`, `node`, `net` or `faults`.
- [ ] Only owned files changed (§3.2).
- [ ] No secrets, keys, `.env`, `dev/`, `data/`, `dist/` committed.
- [ ] Invariants (§13) still hold; say so explicitly if you touched parsing, signing, verdict or the builder.
- [ ] LLD §10 row added for any new decision.

## 10. Sample Go repository (task B1s)

A separate public GitHub repo, `https://github.com/<org>/matrix-hello` (H3), because builders clone from GitHub and genesis only allows `https://github.com/...` URLs.

Template: [examples/sample-repo/](examples/sample-repo/). `scripts/make_sample_repo.sh DIR` builds the git history with every tag below and prints each tag's commit; push it to the public repo.

```
go.mod            module matrix-hello   go 1.23   (no dependencies)
cmd/hello/main.go prints "hello from matrix " + version; var version = "dev"
matrix.toml       image "go1.23", package "./cmd/hello", goos "linux", goarch "amd64",
                  ldflags "-s -w -buildid= -X main.version=<tag>" (per tag), output "hello"
```

A tag can be released only once (`request_id` = hash of repo, commit and tag), so each demo scene uses its own tag. `v1.2.0`..`v1.2.5` have identical code; only the version in the `matrix.toml` ldflags differs, so each tag has its own hash.

| Tag | Purpose (RFC rev 5 §9.2 scenes) | Expected result |
|---|---|---|
| (none) | Scene 1: zero-config founding with `matrix up`; scene 4: imposter on the hotspot | 4 builders online; rogue messages rejected |
| `v1.2.0` | Scene 2: happy path | `CERTIFIED`, hash `TBD` |
| `v1.2.1` | Scene 3: SolarWinds (`inject` on laptop C); scene 5: swapped download uses its backdoored binary, and an older tag's certificate | `CERTIFIED`, honest hash `TBD`; backdoored hash (with `backdoor.patch`) `TBD` |
| `v1.2.2` | Scene 6: a laptop drops off | `CERTIFIED` with 3 of 4, hash `TBD` |
| `v1.2.3` | Scene 7: caught cheater (`equivocate` on laptop B) | `CERTIFIED`, `EQUIVOCATION` evidence, hash `TBD` |
| `v1.2.4`, `v1.2.5` | Spare tags for rehearsals and re-runs | `CERTIFIED`, hashes `TBD` |
| `v0.9.0-broken` | Compile error | `BUILD_FAILED` (exit 5) |
| `v0.9.1-norecipe` | No `matrix.toml` | stays `PENDING` (exit 3) |

`examples/faults/backdoor.patch` is a `git apply` patch against `cmd/hello/main.go` that applies cleanly to every `v1.2.x` tag and adds a visible extra line, for example `fmt.Println("backdoor active")`. Record the honest hash of every tag (and the backdoored hash of `v1.2.1`) as soon as B1 measures them; D5 needs them.

## 11. Sync checkpoints

Short stand-up at each checkpoint. Anything red means re-plan with the RFC §9.4 cut list.

| Hour | Must be true |
|---|---|
| 0.5 | §4 table filled; A1 merged (skeleton, fakes, CI) |
| 1 | Contracts frozen; A2 merged; image pinned; determinism on 4 laptops confirmed (B1) |
| 2 | All laptops reach each other on the phone hotspot (tinc optional); C2 merged |
| 4 | A4 (verdict + model check) merged; B3 builds the sample repo; D1 `verify` works |
| 6 | A5, C3, D2 merged; one builder certifies end to end in compose |
| 8 | 8 builders certify in compose; faults land; the 4-laptop `matrix up` ceremony gives one genesis hash (R4) |
| 10 | Fault matrix green; TUI complete; `DEMO.md` dry run done |
| 11.5 | Feature freeze. Only demo fixes after this. |

## 12. Working with coding agents

### 12.1 Task card (paste this when you start an agent)

```
Task: <ID> — <title from §6>
Track/owner: <A|B|C|D> / <person>
Read first: AGENTS.md, Matrix_RFC_001.md §<x>, docs/LLD.md §<y>, docs/openapi.yaml (if HTTP)
Files you may change: <from §3.2>
Contracts you depend on: <from §5.2>; use tests/fakes.py if not merged yet
Acceptance: <Accept column from §6>
Out of scope: anything not in this card
```

### 12.2 Agent rules

- Read the referenced RFC and LLD sections before writing code. Quote the section you implement in the PR.
- Do not edit files outside the card. Do not change a frozen contract.
- Run `ruff check .`, `ruff format --check .` and `pytest -q` before reporting done. Never report done with failing tests.
- If the spec is ambiguous, stop and ask, or take the simplest option and record it in LLD §10. Never invent protocol behaviour.

### 12.3 Report format (end of every task)

1. Files changed.
2. Tests run, with their pass/fail output.
3. Spec conflicts found (RFC vs LLD vs OpenAPI), if any.
4. LLD §10 rows added, if any.
5. Anything skipped or left as TODO, and why.

## 13. Engineering rules

### 13.1 KISS

1. **No new dependencies** beyond §8.1. Use the standard library for everything else (`sqlite3`, `tomllib`, `hashlib`, `json`, `argparse`, `logging`, `asyncio`).
2. No frameworks or layers that the LLD does not name: no ORM, FastAPI, pydantic, DI container, plugin system or config files beyond genesis and `network.toml`.
3. Plain functions and frozen dataclasses. Use a class only when it holds state (`Store`, `Engine`, `PeerClient`, `Fault`).
4. One module per file listed in LLD §1.
5. No speculative features: no flags, options, retries, caches or abstractions that the spec does not ask for. Nothing from RFC §10.
6. Explicit over clever. Short functions, early returns, comments explain *why*.

### 13.2 Invariants you must never break

These are the security of the system. A change that weakens one is wrong even if the tests pass.

1. **Parsers and `verdict()` never raise** on any input. Hostile input → `None` / ignored.
2. **Canonical JSON** (`canon.canonical_json`) for every hash and signature. No floats in signed data. Duplicate JSON keys are rejected.
3. **Domain-separated signatures:** `b"matrix/v1\0" + genesis_hash + b"\0" + canonical_json(...)`, hellos and endorsements included. Only ceremony founder messages, which exist before genesis, use `b"matrix/v1-founder\0" + network_id + b"\0"`. Never sign or verify raw bodies.
4. **`verdict()` gets its request from the caller**, never from a bundle or peer. `verify` checks the request signature *and* the expected repo, tag and (optional) commit.
5. **Count only** non-equivocating, selected, validly signed attestations for this exact `request_id`. Threshold is `f+1` from genesis.
6. **`FAILED` is a vote only for a deterministic, rerun-confirmed compile error** (LLD §3.8). Every environmental problem is `ERROR` and **abstains**. `BAD_REF` and `BAD_RECIPE` abstain.
7. **Persist before broadcast.** Commit the own attestation to SQLite, then send it. Never sign two different results for one request (except the `equivocate` demo fault).
8. **Subprocesses use argument lists** (`create_subprocess_exec`). Never `shell=True`, never string-built commands.
9. **Build sandbox flags are not optional:** pinned image digest from genesis, `--platform linux/amd64`, `--user uid:gid`, `--cap-drop ALL`, `no-new-privileges`, resource limits, `--network none` for the build step, read-only source and module mounts, `GOTOOLCHAIN=local`, `GOPROXY=https://proxy.golang.org` (no `direct`), ldflags allowlist.
10. **Never join user input onto a filesystem path.** Validate IDs and hashes with `re.fullmatch(..., re.ASCII)` first; look artifacts up in the DB.
11. **Fail closed.** Only exit code 0 means success (RFC §6.4).
12. Fault modes are inert unless the node was started with `--allow-faults`.
13. **Private keys never leave the machine that generated them** (`matrix up` creates them in `~/.matrix/keys/`). Only public keys go into genesis. Test seeds (§5.3) are for tests only.

### 13.3 Layering

Imports only point downward (HLD §4): `canon, crypto, genesis` → `model, select, verdict` → `store, builder` → `protocol, net, faults, discovery` → `node, cli, tui`. The pure layers (bottom two) must not import `asyncio`, `aiohttp`, `sqlite3` or `subprocess`.

### 13.4 Don'ts

- Don't reintroduce commit-reveal, anonymous requests or recipes inside requests. Those were rev 2/3; rev 4 removed them.
- Don't let a builder auto-exclude peers, or change selection based on evidence.
- Don't read the request from a bundle or certificate without verifying it against the caller's expectations.
- Don't treat a timeout, OOM, Docker error, network error or `go mod download` failure as `FAILED`.
- Don't let membership change on connect/disconnect; don't add gossip membership, a DHT, or any signing authority. Membership changes only by re-founding.
- Don't put addresses into ceremony genesis or let anything security-relevant depend on an address. Addresses come from signed hellos and only locate members.
- Don't add HTTP authentication, TLS or a web dashboard. Transport is untrusted by design; signatures carry the security.
- Don't edit the RFC to match your code. If the RFC is wrong, report it.

## 14. Repository layout

```
Matrix_RFC_001.md                       spec (humans only)
AGENTS.md                               this file
docs/HLD.md docs/LLD.md docs/openapi.yaml
docs/OPS.md docs/DEMO.md                per-laptop setup, demo runbook (C1, D5)
matrix/                                 the package (LLD §1, §3)
matrix/discovery.py                     signed UDP hellos, address book, ceremony messages (R1)
network.toml                            network params for the `matrix up` ceremony (R6)
tests/conftest.py tests/fakes.py tests/vectors/     shared test kit (A)
tests/test_*.py                         unit tests
tests/integration/                      Docker + network tests
scripts/dev_genesis.py                  dev keys + genesis (C2)
examples/faults/backdoor.patch          inject demo (B1s)
examples/ci/                            publisher/consumer CI (D5)
genesis.json genesis.demo.json          published copy of the ceremony genesis for consumers (C7)
Dockerfile docker-compose.yml docker-compose.faults.yml .env.example
.github/workflows/ci.yml                CI (A1)
```

## 15. Run it

### 15.1 Four laptops (demo and default)

Once per laptop, follow [docs/OPS.md](docs/OPS.md): WSL2 with mirrored networking on Windows, firewall open for UDP 7788 and TCP 7700, Docker, the same repo checkout (same `network.toml`), all laptops on the phone hotspot.

```bash
python3.11 -m venv .venv && . .venv/bin/activate && pip install -e .
docker pull --platform linux/amd64 golang@sha256:<digest>
matrix up                     # on every laptop: founders appear, Enter to seal,
                              # read the short code aloud, confirm with y; the builder then runs
# laptop A (publisher): matrix tui in a second terminal, then in a third:
matrix release --repo https://github.com/<org>/matrix-hello --tag v1.2.0 --commit <sha> \
  --wait 600 --out dist/      # key ~/.matrix/keys/release.key, addresses from the local node
# any machine with Wi-Fi off, using the published genesis.json and pin:
matrix verify dist/hello --cert dist/hello.matrix.json \
  --repo https://github.com/<org>/matrix-hello --tag v1.2.0
```

Later runs of `matrix up` reuse `~/.matrix/genesis.json` and skip the ceremony. Demo faults: restart one laptop's node with `matrix up --allow-faults --fault MODE [--patch FILE] [--hash HEX]`. Never more than one faulty builder at a time (f = 1).

### 15.2 Single machine (development)

```bash
cp .env.example .env                         # set MATRIX_DATA (absolute), UIDs, DOCKER_GID
mkdir -p "$MATRIX_DATA" dist
docker buildx imagetools inspect golang:1.23 # copy the linux/amd64 digest (H4)
python scripts/dev_genesis.py --out dev --addrs compose --profile demo \
  --repo https://github.com/<org>/matrix-hello --image golang@sha256:<digest>
docker pull --platform linux/amd64 golang@sha256:<digest>
docker compose up -d --build
docker compose run --rm cli release --repo https://github.com/<org>/matrix-hello \
  --tag v1.2.0 --commit <sha> --key /etc/matrix/keys/release.key --wait 600 --out dist/
docker compose run --rm cli tui
```

Without Docker Compose: `python scripts/dev_genesis.py --addrs local ...` and start 8 `matrix-node` processes on `127.0.0.1:7700–7707` (or use `tests/integration/harness.py` from C6).

Demo faults: edit [docker-compose.faults.yml](docker-compose.faults.yml), then `docker compose -f docker-compose.yml -f docker-compose.faults.yml up -d builderN`. Never more than f malicious builders at once (2 in the 8-builder compose network; 1 with `dev_genesis.py --nodes 4`).
