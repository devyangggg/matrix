# Matrix — Low-Level Design

| | |
|---|---|
| **Source of truth** | [RFC-0001 rev 5](../Matrix_RFC_001.md). This LLD turns it into code-level contracts. If they disagree, the RFC wins: fix the LLD. |
| **Overview** | [HLD](HLD.md) |
| **HTTP contract** | [openapi.yaml](openapi.yaml) |

## 0. Conventions

- Python 3.11+, `asyncio` everywhere in the daemon. Type hints on every public function.
- Runtime dependencies: `pynacl`, `aiohttp`, `textual`. Dev: `pytest`, `pytest-asyncio`, `ruff`. **Nothing else.**
- Plain functions and frozen `@dataclass`es. Write a class only when it holds state (`Store`, `Engine`, `PeerClient`, `AddressBook`, `Discovery`).
- Parsers and `verdict()` **never raise**. They return `None` or a `Verdict`. Wrap the body in `try/except Exception: return None` as a last line of defence, but validate explicitly first.
- Regexes always use `re.fullmatch(..., re.ASCII)`.
- Subprocesses always use `asyncio.create_subprocess_exec` with an argument list. Never `shell=True`.
- Time comes from an injectable `clock: Callable[[], float] = time.time`, so tests can control it.
- Logging: stdlib `logging`, one line per event, prefixed with the node ID.

## 1. Package and files

```
pyproject.toml           # name "matrix", scripts: matrix-node = matrix.node:main, matrix = matrix.cli:main
matrix/
  __init__.py            # __version__ = "0.1.0"
  canon.py  crypto.py  genesis.py  model.py  select.py  verdict.py
  store.py  builder.py  protocol.py  net.py  discovery.py  faults.py
  node.py   cli.py      tui.py
network.toml             # network parameters for the founding ceremony (§4.2)
scripts/dev_genesis.py   # dev keys + genesis generator, static addrs (§12)
tests/                   # §11
examples/faults/backdoor.patch
genesis.json  genesis.demo.json   # published copies of the founded genesis, for consumers
Dockerfile  docker-compose.yml  docker-compose.faults.yml  .env.example
```

Exact `pyproject.toml`: [AGENTS.md §8.1](../AGENTS.md). Shared test kit (`tests/conftest.py`, `tests/fakes.py`, `tests/vectors/`): [AGENTS.md §5.3](../AGENTS.md).

## 2. Constants

All protocol parameters come from genesis. Only these are code constants (`matrix/model.py` unless noted):

| Name | Value | Source |
|---|---|---|
| `PROTOCOL_V` | `1` | RFC §7.3 |
| `SIG_PREFIX` | `b"matrix/v1\0"` | RFC §7.4 |
| `MAX_RELEASE_ENV` | 4096 bytes | RFC §7.4 |
| `MAX_ATTEST_ENV` | 1024 bytes | RFC §7.4 |
| `MAX_RECIPE` | 4096 bytes | RFC §7.3 |
| `MAX_CERT` | 65536 bytes | LLD |
| `MAX_ARTIFACT` | 64 MiB (`builder.py`) | RFC §4 |
| `MIN_FREE_DISK` | 2 GiB (`builder.py`) | RFC §7.10 |
| `MAX_LOG` | 1 MiB written, 64 KiB served (`builder.py`) | RFC §7.10 |
| `ARTIFACT_RETENTION_S` | 86400 (`protocol.py`) | RFC §4 |
| `INGEST_PER_MIN` | 20 (`protocol.py`) | RFC §7.6 |
| `HTTP_TIMEOUT_S` | 3 (`net.py`) | LLD |
| `RELEASE_POLL_S` | 2 (`cli.py`) | LLD |
| `DISCOVERY_PORT` | 7788, UDP (`discovery.py`) | RFC rev 5 |
| `HELLO_INTERVAL_S` | 5 (`discovery.py`) | RFC rev 5 |
| `ONLINE_WINDOW_S` | 15 (`discovery.py`) | RFC rev 5 |
| `MAX_HELLO` | 512 bytes (`discovery.py`) | RFC rev 5 |
| `FOUNDER_INTERVAL_S` | 2 (`discovery.py`) | RFC rev 5 |
| `CEREMONY_TIMEOUT_S` | 300 (`discovery.py`) | RFC rev 5 |
| `MAX_CEREMONY` | 1024 bytes, founder and endorse datagrams (`discovery.py`) | LLD (L39) |
| `MAX_SEAL` | 2048 bytes, seal proposals (`discovery.py`) | LLD (L54) |
| `FOUNDER_PREFIX` | `b"matrix/v1-founder\0"` (`discovery.py`) | RFC rev 5 |

## 3. Module contracts

### 3.1 `canon.py` (pure)

```python
def canonical_json(obj: Any) -> bytes
    # json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    #            allow_nan=False).encode("utf-8"). Raises TypeError on floats (callers
    #            only pass str/int/bool/None/list/dict; this is a programming error, not input).
def sha256_hex(data: bytes) -> str
def loads_strict(data: bytes | str) -> Any | None
    # json.loads with object_pairs_hook that returns None on duplicate keys,
    # parse_float that rejects floats, parse_constant that rejects NaN/Infinity.
    # Returns None on any error. Never raises.
```

`canonical_json` must reject floats anywhere: walk the object or use a `default=` that raises. Booleans are not ints for our schemas: check `type(x) is int`.

### 3.2 `crypto.py` (pure)

```python
def keygen() -> tuple[str, str]                  # (seed_hex, pubkey_hex), 32-byte seed
def load_key(path: str) -> nacl.signing.SigningKey  # file = 64 hex chars + optional newline
def pubkey_hex(sk) -> str
def signed_bytes(genesis_hash: str, unsigned: dict) -> bytes
    # SIG_PREFIX + genesis_hash.encode("ascii") + b"\0" + canonical_json(unsigned)
    # unsigned = {"v", "type", "signer", "body"}
def sign(sk, genesis_hash: str, unsigned: dict) -> str     # 128 hex
def verify(pubkey_hex: str, genesis_hash: str, unsigned: dict, sig_hex: str) -> bool
    # never raises; False on any error
```

`matrix keygen --out F` writes the seed hex to `F` with mode `0600` and prints the public key hex. `matrix up` creates `~/.matrix/keys/node.key` and `release.key` the same way if they are absent (§3.13).

### 3.3 `genesis.py` (pure)

```python
@dataclass(frozen=True)
class Node:   id: str; operator: str; addr: str | None; pubkey: str   # addr "host:port", optional
@dataclass(frozen=True)
class Signer: id: str; pubkey: str

@dataclass(frozen=True)
class Genesis:
    network_id: str; f: int; replicas: int; threshold: int
    build_timeout_s: int; request_ttl_s: int; sync_interval_s: int
    allowed_repos: tuple[str, ...]; allowed_images: dict[str, str]
    allowed_goos: tuple[str, ...]; allowed_goarch: tuple[str, ...]
    release_signers: tuple[Signer, ...]; nodes: tuple[Node, ...]
    hash: str                                   # sha256_hex(canonical_json(raw genesis))
    def node(self, id: str) -> Node | None
    def signer(self, id: str) -> Signer | None

def load_genesis(path: str) -> Genesis          # raises GenesisError with a clear message
def parse_genesis(raw: dict) -> Genesis         # raises GenesisError
def file_genesis_hash(path: str) -> str         # canonical hash, used for pinning
```

Validation (raise `GenesisError`, refuse to start):

- Exactly the top-level keys of RFC §7.2. Every int is `type(x) is int` and > 0.
- `n = len(nodes)`: `n >= 4*f`, `2*f+1 <= replicas <= n`, `threshold == f+1`, `build_timeout_s < request_ttl_s`.
- Node and signer IDs match `[A-Za-z0-9_-]{1,32}`, are unique **across both lists**; all pubkeys are 64 lowercase hex and distinct.
- Every node has a non-empty `operator`; no operator has more than `f` nodes (more than 1 when f = 0). `f = 0` is allowed (L53).
- Node keys are exactly `{id, operator, pubkey}` or `{id, operator, addr, pubkey}`. `addr` is optional (`None` when absent) and, when present, matches `[A-Za-z0-9.-]+:[0-9]{1,5}`. Ceremony genesis omits it (addresses come from hellos, §3.10a); dev genesis keeps static addrs (§12). Addresses are not security relevant: an IP in genesis would change the hash whenever DHCP does.
- `allowed_repos` entries match `https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`.
- `allowed_images` values match `[a-z0-9./_-]+@sha256:[0-9a-f]{64}`.
- All allowlists and `release_signers` are non-empty.

The **genesis hash** is always the hash of canonical JSON, never of file bytes. The pinned value (`~/.matrix/genesis.sha256`, `--genesis-sha256`) is this hash.

### 3.4 `model.py` (pure)

```python
@dataclass(frozen=True)
class Request:  v: int; repo_url: str; commit: str; tag: str
@dataclass(frozen=True)
class Recipe:   image: str; package: str; goos: str; goarch: str; ldflags: str; output: str
@dataclass(frozen=True)
class Envelope:
    type: str; signer: str; body: dict; sig: str
    raw: dict                       # the full envelope as parsed
    msg_id: str                     # sha256_hex(canonical_json(raw))
@dataclass(frozen=True)
class Certificate:
    genesis_hash: str; request: dict; attestations: tuple[dict, ...]

def request_id(body: dict) -> str                         # sha256_hex(canonical_json(body))
def valid_request(body: Any, g: Genesis) -> bool          # RFC §7.3 request rules
def parse_recipe(data: bytes, g: Genesis) -> Recipe | None  # RFC §7.3 recipe rules (tomllib)
def valid_ldflags(s: str) -> bool
def make_envelope(type: str, signer: str, body: dict, sk, g: Genesis) -> dict
def parse_envelope(raw: Any, g: Genesis) -> Envelope | None      # a.k.a. Envelope.parse
def parse_certificate(raw: bytes, g: Genesis) -> Certificate | None
```

`parse_envelope(raw, g)` (`raw` may be `bytes`, `str` or `dict`):

1. If bytes/str: reject if longer than `MAX_RELEASE_ENV`; `loads_strict`. Must be a dict.
2. Keys exactly `{v, type, signer, body, sig}`; `v` is int 1; `type in {"release","attest"}`; `signer` str; `body` dict; `sig` matches `[0-9a-f]{128}`.
3. `len(canonical_json(raw)) <=` 4096 for release, 1024 for attest.
4. Body:
   - release: `valid_request(body, g)` (keys exactly `{v, repo_url, commit, tag}`, `repo_url in g.allowed_repos`, `commit` `[0-9a-f]{40}`, `tag` `[A-Za-z0-9_.+-]{1,64}`).
   - attest: keys exactly `{request_id, result}`; `request_id` `[0-9a-f]{64}`; `result` `[0-9a-f]{64}` or `"FAILED"`.
5. Signer: release → `g.signer(signer)`; attest → `g.node(signer)`. Unknown → `None`.
6. `crypto.verify(pubkey, g.hash, {v,type,signer,body}, sig)`.

`valid_ldflags(s)`: `s == ""` or (`len(s) <= 512` and tokens = `s.split(" ")` where each token is `-s`, `-w`, `-buildid=`, or `-X` followed by a token matching `[A-Za-z0-9_./-]+\.[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:@+-]{0,128}`). Empty tokens (double spaces) are rejected.

`parse_recipe`: `len(data) <= 4096`; `tomllib.loads(data.decode("utf-8"))`; top level keys exactly `{"build"}`; build keys exactly `{image, package, goos, goarch, ldflags, output}`, all `str`; `image in g.allowed_images`; goos/goarch in allowlists; `package` matches `\./[A-Za-z0-9_./-]*` with no `..` path component; `valid_ldflags`; `output` matches `[A-Za-z0-9_.-]{1,64}` and is not `.` or `..`.

`parse_certificate`: `len(raw) <= MAX_CERT`; `loads_strict`; keys exactly `{v, genesis_hash, request, attestations}`; `v == 1`; `genesis_hash` 64 hex; `request` dict; `attestations` list of dicts, `1 <= len <= 2 * len(g.nodes)`. It does **not** check signatures; `verify` does that through `parse_envelope` and `verdict`.

### 3.5 `select.py` (pure)

Exactly RFC §7.5:

```python
def selected(request_id: str, nodes: Sequence[Node], r: int) -> list[str]
```

### 3.6 `verdict.py` (pure)

```python
@dataclass(frozen=True)
class Verdict:
    state: str                     # AGREED | BUILD_FAILED | NOT_REPRODUCIBLE | PENDING | INVALID
    hash: str | None = None        # set for AGREED
    results: dict[str, str] = field(default_factory=dict)   # signer -> result (non-equivocators)
    equivocators: frozenset[str] = frozenset()

def verdict(request_env: Any, envelopes: Iterable[Any], g: Genesis) -> Verdict
```

Implement RFC §7.7 line for line. `results`/`equivocators` are only for display and evidence. `INVALID` means the request envelope itself is bad (callers map it: `verify` → `INVALID_CERT`; `release`/`status` → error, exit 4).

### 3.7 `store.py` (SQLite)

One `sqlite3.Connection`, opened with `isolation_level=None` (explicit transactions), `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `PRAGMA foreign_keys=ON`. Schema exactly RFC §7.8, created with `CREATE TABLE IF NOT EXISTS`.

**Single writer:** the connection is only used from the event-loop thread. Calls are synchronous and short; no thread pool, no locks. This is the "single writer task" of the RFC.

```python
class Store:
    def __init__(self, path: str)
    # requests
    def add_request(self, rid: str, env: dict, now: float, phase: str) -> bool   # False if known
    def get_request(self, rid: str) -> sqlite3.Row | None
    def list_requests(self, since: float) -> list[sqlite3.Row]                    # received_at >= since
    def live_requests(self, now: float, ttl: int) -> list[sqlite3.Row]            # received_at > now - ttl
    def set_phase(self, rid: str, phase: str) -> None
    # attestations
    def add_attestation(self, e: Envelope, now: float) -> bool     # INSERT OR IGNORE by msg_id
    def attestation_count(self, rid: str, signer: str) -> int
    def attestations(self, rid: str) -> list[dict]                 # envelopes, ordered by received_at
    # own builds
    def get_build(self, rid: str) -> sqlite3.Row | None
    def upsert_build(self, rid: str, **fields) -> None
    def record_own_attestation(self, rid: str, result: str, artifact_path: str | None,
                               env: Envelope, now: float) -> None
        # ONE transaction: my_builds.result/artifact_path/finished_at, INSERT attestation,
        # phase = ATTESTED. Called BEFORE broadcasting (RFC §7.6 rule 4).
    def artifact_path(self, sha256: str) -> str | None   # SELECT artifact_path FROM my_builds WHERE result = ?
    # evidence
    def add_evidence(self, kind: str, signer: str, rid: str, proof: list | None, now: float) -> bool
    def list_evidence(self, since: float) -> list[sqlite3.Row]
```

### 3.8 `builder.py`

```python
@dataclass(frozen=True)
class BuildEnv:
    data_dir: str            # <data>; work/, logs/, artifacts/ live under it
    node_id: str
    uid: int; gid: int       # os.getuid(), os.getgid()
    runtime: str | None = None   # "runsc" (gVisor) when the daemon has it, from isolation()

@dataclass(frozen=True)
class Outcome:
    kind: str                # HASH | FAILED | ERROR | BAD_REF | BAD_RECIPE
    result: str | None       # sha256 hex for HASH, "FAILED" for FAILED, else None
    artifact_path: str | None
    reason: str              # short human-readable reason, stored in my_builds.error

async def build(req: Request, rid: str, g: Genesis, env: BuildEnv, attempt: int,
                patch: str | None = None) -> Outcome
def classify_go_build(rc: int, stderr: str, rerun_rc: int | None, rerun_stderr: str | None,
                      workdir: str) -> str      # FAILED | ERROR (pure, unit-tested)
async def cleanup_startup(env: BuildEnv) -> None   # rm work/*, docker rm -f mx-<node_id>-*
def expire_artifacts(env: BuildEnv, now: float) -> None
async def isolation() -> tuple[str | None, str]    # (runtime, description); never raises
```

`isolation()` reads `docker info --format '{{json .Runtimes}}'`: if `runsc` is registered it returns `("runsc", ...)`, and every build container runs on gVisor's user-space kernel. Otherwise `None`, described as Docker Desktop's VM on macOS and as a warning (builds share the host's Linux kernel) elsewhere. The node calls it once at startup; `matrix up` prints the description. gVisor does not change build output (v1.2.0 gives the same hash under `runc` and `runsc`).

Paths for one attempt: `W = <data>/work/<rid>`; `W/src`, `W/out`, `W/gomod`; log `<data>/logs/<rid>.log`; artifact `<data>/artifacts/<sha256>`.

`build()` steps. The whole call is wrapped by the caller in `asyncio.wait_for(..., g.build_timeout_s)`. On `CancelledError`/timeout, kill the running step (see below) and re-raise; the caller maps it to `ERROR`.

| # | Action | Failure → |
|---|---|---|
| 0 | `shutil.disk_usage(data_dir).free >= MIN_FREE_DISK`; `rm -rf W`; `docker rm -f` this attempt's container names | `ERROR` |
| 1a | `git clone --filter=blob:none --no-checkout <repo> W/src` (env `GIT_TERMINAL_PROMPT=0`) | `ERROR` |
| 1b | `git -C W/src fetch --no-tags origin +refs/tags/<tag>:refs/tags/<tag>` | stderr has a not-found marker → `BAD_REF`, else `ERROR` |
| 1c | `git -C W/src checkout --detach <commit>` | not-found marker → `BAD_REF`, else `ERROR` |
| 1d | `rev-parse HEAD == commit` and `rev-parse refs/tags/<tag>^{commit} == commit` | `BAD_REF` |
| 1e | (fault `inject` only) `git -C W/src apply <patch>` | `ERROR` |
| 1f | `parse_recipe(read W/src/matrix.toml)`; also `du W/src <= 512 MiB` | `BAD_RECIPE` / `ERROR` |
| 2 | `docker run ... go mod download` (RFC §7.10 step 2) | any failure → `ERROR` |
| 3 | `docker run ... --network none ... go build` (RFC §7.10 step 3) | `classify_go_build` |
| 4 | hash `W/out/<output>`; size ≤ 64 MiB; copy to `artifacts/<h>.tmp`, fsync, rename, fsync dir | `ERROR` |
| — | `finally`: `rm -rf W` (always) | |

Not-found markers (BAD_REF): `couldn't find remote ref`, `did not match any`, `reference is not a tree`, `unknown revision`, `not our ref`. Mixing up `BAD_REF` and `ERROR` is harmless, because both abstain. Only retries differ.

Common docker flags (build them in one function, `docker_common(env, rid, attempt, step) -> list[str]`):

```
--rm [--runtime runsc] --platform linux/amd64 --user <uid>:<gid> --cap-drop ALL
--security-opt no-new-privileges --memory 2g --cpus 1 --pids-limit 512
--name mx-<node_id>-<rid[:8]>-<attempt>-<step>
-e HOME=/tmp -e GOTOOLCHAIN=local -e GOFLAGS=-mod=readonly -modcacherw
```

`GOFLAGS` is a single argv element: `-e`, `GOFLAGS=-mod=readonly -modcacherw`. The image is `g.allowed_images[recipe.image]`, the full `name@sha256:` reference.

`classify_go_build(rc, stderr, rerun_rc, rerun_stderr, workdir)`:

- `rc in (125, 126, 127, 137)` or `rc not in (0, 1)` → `ERROR`.
- `rc == 1` and stderr contains any of `signal: killed`, `cannot allocate memory`, `no space left on device`, `resource temporarily unavailable` → `ERROR`.
- `rc == 1`: the caller reruns step 3 once (same container name with suffix `-r`). If `rerun_rc == 1` and `rerun_stderr.replace(workdir, "") == stderr.replace(workdir, "")` → `FAILED`; else `ERROR`.

Running a step: `proc = await create_subprocess_exec(*argv, stdout=PIPE, stderr=PIPE, start_new_session=True)`; `out, err = await proc.communicate()`; append both to the log until it reaches 1 MiB. On cancellation: `os.killpg(proc.pid, SIGTERM)`, wait 5 s, `SIGKILL`; for docker steps also `docker kill <name>`.

### 3.9 `protocol.py` (engine)

```python
class Engine:
    def __init__(self, g: Genesis, me: Node, sk, store: Store, peers: "PeerClient",
                 env: BuildEnv, fault: Fault, clock=time.time)
    async def on_request(self, raw: bytes | dict) -> tuple[int, dict]   # HTTP status, JSON body
    async def on_attest(self, raw: bytes | dict, from_hint: str | None) -> tuple[int, dict]
    async def build_worker(self) -> None            # exactly one task
    async def sync_loop(self) -> None               # pull sync + housekeeping
    async def recover(self) -> None                 # startup (§5)
    def detect_evidence(self, rid: str) -> None
    def is_settled(self, rid: str) -> bool
```

State in memory (rebuilt on restart; everything else is in SQLite):

- The build queue is the store itself: live requests in phase `RECEIVED`, oldest `received_at` first (`Engine.queued()`). `wake = asyncio.Event()` only wakes the worker. Nothing is shed (L30).
- `ingest = collections.deque()`: timestamps of new requests in the last 60 s.
- `cursors: dict[node_id, float]`: pull-sync cursor per peer (peer's `now`).

**`on_request(raw)`**

1. `e = parse_envelope(raw, g)`. If `None`: 403 `forbidden` if `raw` is a dict whose `signer` is not a release signer, else 400 `invalid_envelope`. If `e.type != "release"` → 400.
2. `rid = request_id(e.body)`. Known → 202 `{id}` (idempotent, no forward).
3. Ingest cap: drop timestamps older than 60 s; if `len >= 20` → 429 `rate_limited`.
4. `fault.on_new_request()` (`crash` exits here).
5. Store with `t0 = now`, phase `RECEIVED` if `me.id in selected(...)` else `OBSERVING`. `peers.broadcast_request(e.raw)`.
6. If selected: wake the worker (the request is already queued as `RECEIVED`). Return 202 `{id}`.

**`build_worker()`** loops forever:

1. `rid = queued()[0]`, or wait for `wake`. Already attested → phase `ATTESTED`, skip. Otherwise pull this request's bundle from every peer through `on_attest` (L31), then skip (phase `MISSED`, reason `settled`) if `is_settled(rid)`.
2. `fault.attest_without_build()` returns a result for `lie`/`collude`; `stall` returns the sentinel `STALL` → leave phase `RECEIVED`, `continue`.
3. Phase `BUILDING`, `upsert_build(started_at=now)`. Attempt loop `attempt = 0..2`:
   `outcome = await wait_for(build(..., attempt, patch=fault.patch), g.build_timeout_s)` (timeout → `ERROR`).
   `HASH`/`FAILED` → break. `BAD_REF`/`BAD_RECIPE` → break. `ERROR` → retry only if `now + build_timeout_s < t0 + request_ttl_s`.
4. `HASH`/`FAILED` → `attest(rid, result, artifact_path)`. Otherwise phase `MISSED`, `my_builds.error = reason`.

**`attest(rid, result, artifact)`**: `env = make_envelope("attest", me.id, {request_id, result}, sk, g)`; `store.record_own_attestation(...)` (commits); then `fault.broadcast(env)` → normally `peers.broadcast_attest(env)`. `equivocate` signs a second envelope with a different random result and sends it to the other half of the peers. Then `detect_evidence(rid)`.

**`on_attest(raw, from_hint)`**

1. `len(raw) > 1024` → 413. `e = parse_envelope(raw, g)`; `None` or not `attest` → 400.
2. Request unknown → if `from_hint` names a genesis node, `GET /v1/requests/{id}` from it and run it through `on_request` (must hash to `request_id`). Still unknown → 409 `unknown_request`. Pull sync will bring it later.
3. Request older than `request_ttl_s` → 409 `expired`.
4. Signer not in selected set → 400. `attestation_count(rid, signer) >= 2` and this `msg_id` is new → 202 (ignored, cap reached).
5. `add_attestation`; if new → `detect_evidence(rid)`. Return 202 `{msg_id}`.

**`detect_evidence(rid)`** (idempotent thanks to the UNIQUE constraint):

- Group stored attestations by signer. Two or more distinct results → `EQUIVOCATION`, proof = two conflicting envelopes.
- `v = verdict(request_env, attestations, g)`. If `AGREED(h)` or `BUILD_FAILED` (quorum result `"FAILED"`): every non-equivocating signer whose result differs → `DISAGREE`, proof = `[its envelope]`.
- `now > t0 + 2 * build_timeout_s`: every selected signer with no attestation → `STALL`, proof `None`.

**`is_settled(rid)`** = `verdict(...).state != "PENDING"` or `now - t0 > request_ttl_s`.

**`sync_loop()`** every `g.sync_interval_s` (all peer calls concurrently with `asyncio.gather`, errors ignored per peer):

1. For each peer: `GET /v1/requests?since=max(0, cursor-60)` → `{now, requests}`; save `cursor = now`. For each unknown `id` whose `now - received_at <= request_ttl_s`: `GET /v1/requests/{id}` → `on_request(request)` (respects the ingest cap; skipped ones are retried next round because the cursor overlaps by 60 s; if the cap keeps skipping, the next startup with cursor 0 recovers them).
2. For each `store.live_requests(now, ttl)`: `GET /bundle` from each peer, `on_attest(env, from_hint=peer)` for each envelope.
3. Housekeeping: `detect_evidence` for live requests (catches `STALL`); `expire_artifacts` once an hour.

### 3.10 `net.py`

```python
def make_app(engine: Engine, store: Store, g: Genesis, me: Node, env: BuildEnv,
             book: AddressBook | None = None) -> web.Application
class PeerClient:
    def __init__(self, g: Genesis, me: Node, book: AddressBook | None = None)
        # peers = every node except me
    async def broadcast_request(self, env: dict) -> None   # fire-and-forget tasks
    async def broadcast_attest(self, env: dict, only: list[str] | None = None) -> None
    async def get_json(self, node_id: str, path: str) -> Any | None   # None on any error
    async def get_json_at(self, url: str) -> Any | None    # explicit URL (the CLI's local builder)
    async def get_bytes(self, node_id: str, path: str, limit: int) -> bytes | None
    async def close(self) -> None
```

- Address of a peer: `book.addr(id)` (latest verified hello, §3.10a), else genesis `node.addr`, else unreachable (pushes skip it, `get_*` return `None`). The book is read on every call, so a new DHCP address is used as soon as its hello arrives.
- One `aiohttp.ClientSession` with `ClientTimeout(total=HTTP_TIMEOUT_S)`. Pushes add header `X-Matrix-From: <me.id>`. That header is only a hint for where to fetch an unknown request. It is never trusted.
- `web.Application(client_max_size=4096)`. Handlers read `await request.read()` and pass the bytes to the engine. Routes and payloads are in [openapi.yaml](openapi.yaml).
- Errors are `{"error": "<code>", "detail": "<text>"}` with codes `invalid_envelope`, `forbidden`, `too_large`, `rate_limited`, `unknown_request`, `expired`, `not_found`.
- `GET /v1/artifacts/{sha256}`: path param must match `[0-9a-f]{64}`, else 404. Look up the path with `store.artifact_path(sha)`; never join user input onto a path. Stream with `web.FileResponse`. If the fault is `bad-artifact`, return the bytes with the first byte XOR `0xFF`.
- `GET /v1/requests/{id}/log`: **loopback callers only** (`request.remote` in `127.0.0.1`, `::1`, `::ffff:127.0.0.1`); anyone else gets 404 `not_found`, so a log's existence is not revealed. Logs show host details (paths, uids, toolchain output); requests, attestations and evidence stay public so anyone can recount votes. Then: `id` validated as 64 hex, last 64 KiB of `logs/<id>.log` as `text/plain`, 404 if absent.
- `GET /v1/peers`: `{"now": clock(), "hellos": book.hellos()}` (`hellos: []` without a book or with `--no-discovery`). Untrusted: clients re-verify every hello against genesis (§3.10a) before using its address.
- Server binds to the `--listen` address (`0.0.0.0:7700` with `matrix up` and inside a container).

### 3.10a `discovery.py` (signed hellos and the founding ceremony)

Locates members and founds the network. It never changes membership: that is fixed by genesis (RFC D3). Standard library `socket` and `asyncio` only. One UDP socket per phase on `0.0.0.0:DISCOVERY_PORT` with `SO_BROADCAST` and `SO_REUSEADDR` (so a second process on the host can still bind). One canonical JSON message per datagram. A running node reads only `hello`; the ceremony reads only `founder` and `endorse`; everything else is dropped.

```python
@dataclass(frozen=True)
class Hello:   signer: str; addr: str; seq: int; raw: dict     # addr "<IPv4>:<port>", seq unix ms

def make_hello(g: Genesis, me: Node, sk, addr: str, seq: int) -> bytes
    # canonical_json({"v":1, "type":"hello", "signer":me.id,
    #   "body":{"genesis_hash":g.hash, "addr":addr, "seq":seq}, "sig":crypto.sign(sk, g.hash, unsigned)})
def parse_hello(data: bytes | dict, g: Genesis,
                last_seq: Mapping[str, int] | None = None) -> Hello | None   # never raises
def local_ip() -> str | None
    # source address the OS picks for 255.255.255.255:DISCOVERY_PORT (UDP connect + getsockname);
    # None on error or "0.0.0.0"

class AddressBook:                                   # in memory only
    def __init__(self, g: Genesis, clock=time.time)
    seqs: dict[str, int]                             # last accepted seq per signer (check 4)
    def accept(self, data: bytes | dict) -> Hello | None   # parse_hello(data, g, self.seqs), then update
    def update(self, h: Hello) -> bool               # (addr, seq, last_seen=clock(), raw); True if addr new/changed
    def addr(self, node_id: str) -> str | None
    def online(self, node_id: str, now: float) -> bool     # now - last_seen < ONLINE_WINDOW_S
    def hellos(self) -> list[dict]                   # latest accepted envelope per node, sorted by signer

class Discovery:
    def __init__(self, g: Genesis, me: Node, sk, book: AddressBook, listen_port: int,
                 advertise: str | None = None, port: int = DISCOVERY_PORT, clock=time.time)
    async def run(self) -> None                      # bind, announce, listen; until cancelled
```

`parse_hello` runs the receiver checks cheapest first, so size and membership are checked before the signature and per-packet work is bounded. Any failure → `None`; a private `_check_hello` returns the reason for the `hello.reject` log line.

| # | Check | Reason |
|---|---|---|
| 1 | `len(data) <= MAX_HELLO` (a dict: its canonical JSON); `loads_strict`; keys exactly `{v, type, signer, body, sig}`; `v` int 1; `type == "hello"`; body keys exactly `{genesis_hash, addr, seq}`; `addr` matches `[0-9]{1,3}(\.[0-9]{1,3}){3}:[0-9]{1,5}` with octets ≤ 255 and port 1–65535; `seq` is `type(x) is int`, ≥ 0; `sig` 128 hex | `size` / `parse` |
| 2 | `g.node(signer)` exists | `signer` |
| 3 | `body.genesis_hash == g.hash` | `genesis` |
| 4 | `seq > last_seq.get(signer, -1)` (anti-replay) | `replay` |
| 5 | `crypto.verify(node.pubkey, g.hash, {v, type, signer, body}, sig)` | `sig` |

A stranger fails 2, a forgery 5, a replay 4. A member can only advertise a wrong address for itself, which makes only itself unreachable (liveness, never safety).

`Discovery.run()`:

- Bind, or raise (the node refuses to start, §3.12). The announce loop wakes every 1 s. Advertised address = `advertise` if set, else `f"{local_ip()}:{listen_port}"`; no local IP → skip the round.
- Send a hello at startup, every `HELLO_INTERVAL_S`, and at once when the advertised address changes. Every hello carries a fresh `seq = max(int(clock() * 1000), last_sent + 1)`, because receivers drop a repeated seq. Send to `("255.255.255.255", port)` and to every `broadcast_targets()` address (L55), then `book.update(own hello)`, so `/v1/peers` lists this node too. The own broadcast that comes back fails check 4 harmlessly.
- Receive (`asyncio.DatagramProtocol`): `h = book.accept(data)`. If `update` reported a new or changed address, also unicast the latest own hello to `(host of h.addr, port)` (fast convergence). Log `peer.online` / `peer.addr` on transitions and `peer.offline` when a node leaves the online window.
- Send errors (no network, Wi-Fi off) are logged at DEBUG and retried next round. Callbacks never raise.

**Founding ceremony** messages and helpers (plain functions, no I/O except `load_network` and `default_name`; driven by `matrix up`, §3.13):

```python
@dataclass(frozen=True)
class Founder: id: str; pubkey: str; release_pubkey: str; params_hash: str; raw: dict
@dataclass(frozen=True)
class Endorse: signer: str; genesis_hash: str; raw: dict
@dataclass(frozen=True)
class Seal: signer: str; genesis_hash: str; founders: tuple[tuple[str, str], ...]; raw: dict  # (name, pubkey), sorted by pubkey

def load_network(path: str) -> dict            # the [network] table of network.toml; raises NetworkError
def params_hash(params: dict) -> str           # sha256_hex(canonical_json(params))
def default_name() -> str                      # hostname rule below
def founder_bytes(network_id: str, unsigned: dict) -> bytes
    # FOUNDER_PREFIX + network_id.encode("ascii") + b"\0" + canonical_json(unsigned)
def make_founder(params: dict, name: str, sk, release_sk) -> bytes
    # body.release_sig: release_sk signs founder_bytes(network_id, {pubkey, release_pubkey})
def parse_founder(data: bytes, network_id: str) -> Founder | None           # never raises
def seal_problem(params: dict, founders: Sequence[Founder], me_pubkey: str) -> str | None
def ceremony_genesis(params: dict, founders: Sequence[Founder]) -> dict     # raw genesis
def short_code(genesis_hash: str) -> str       # "3F2A-9C1D-77E0-41B8"
def make_endorse(g: Genesis, me: Node, sk) -> bytes
def parse_endorse(data: bytes, pubkeys: Mapping[str, str]) -> Endorse | None   # id -> pubkey; never raises
def make_seal(network_id: str, sk, founders: Sequence[Founder], genesis_hash: str) -> bytes
def parse_seal(data: bytes, network_id: str) -> Seal | None                   # never raises
def broadcast_targets() -> list[str]           # "255.255.255.255" + each interface's broadcast address (L55)
def check_endorsements(g: Genesis, envs: Iterable[Any]) -> bool
    # True iff every node in g has a valid endorse of g.hash, verified with its genesis pubkey
```

- `load_network`: `tomllib`; top-level keys exactly `{network}`; `[network]` keys exactly `{name, allowed_repos, allowed_images, allowed_goos, allowed_goarch, build_timeout_s, request_ttl_s, sync_interval_s}`; `name` matches `[A-Za-z0-9_.-]{1,64}` (the genesis `network_id` rule); lists of `str`, `allowed_images` a table of `str`, ints `type(x) is int`. Value rules are left to `parse_genesis` on the built genesis.
- `default_name`: `socket.gethostname().lower()`, every character outside `[a-z0-9_-]` replaced by `-`, cut to 24. Names (also `--name`) must match `[A-Za-z0-9_-]{1,24}`.
- Founder signature: `sk.sign(founder_bytes(network_id, unsigned)).signature.hex()`, verified with `nacl.signing.VerifyKey` inside `try`. The separate prefix means a founder signature can never be replayed as an envelope, and the reverse.
- `parse_founder`: `len(data) <= MAX_CEREMONY`; `loads_strict`; keys exactly `{v, type, signer, body, sig}`; `v` 1; `type == "founder"`; body keys exactly `{network_id, id, pubkey, release_pubkey, release_sig, params_hash}`; `body.network_id == network_id` (other networks on the hotspot are ignored); `id` matches the name rule; `signer`, `pubkey`, `release_pubkey`, `params_hash` 64 lowercase hex; `signer == body.pubkey`; `release_pubkey != pubkey`; `release_sig` verifies with `release_pubkey` over `founder_bytes(network_id, {pubkey, release_pubkey})` (a founder cannot claim someone else's release key, L49); the signature verifies with `signer` (proof of possession).
- `parse_endorse`: `len(data) <= MAX_CEREMONY`; exact envelope keys; `type == "endorse"`; body keys exactly `{genesis_hash}`, 64 hex; `pubkeys[signer]` exists; `crypto.verify(pubkey, body.genesis_hash, unsigned, sig)`. It is verified with the hash it carries, so an endorsement that arrives before the local seal is kept; it counts only if that hash equals ours (L42).
- `seal_problem` returns a reason, or `None` to allow a proposal: at least 2 founders (L53); unique ids; every `params_hash == params_hash(params)`; `me_pubkey` listed; `parse_genesis(ceremony_genesis(...))` succeeds.
- `make_seal` / `parse_seal` (L54): `type == "seal"`, signed with the node key over `founder_bytes(network_id, unsigned)`; body keys exactly `{network_id, genesis_hash, founders}`; `founders` is a list of 1 to 16 `{id, pubkey}` (name rule, 64 hex), sorted by and distinct in `pubkey`, containing `signer`; `len(data) <= MAX_SEAL`; the signature verifies with `signer`.
- `ceremony_genesis` (deterministic: same founders and `network.toml` → byte-identical canonical genesis → same hash on every laptop): `n = len(founders)`, `f = n // 4`, `replicas = n`, `threshold = f + 1`; `network_id = params["name"]`; the other seven parameters copied from `params`; `nodes` sorted by `pubkey` as `{id, operator: id, pubkey}` (no `addr`); `release_signers` sorted by their `pubkey` as `{id: id + "-rel", pubkey: release_pubkey}`.
- `short_code(h)`: `h[:16].upper()` in groups of 4 joined by `-` (64 bits: too many to grind in a one-minute ceremony).

Ceremony steps (`cli.ceremony`; nothing is written until step 7):

1. Keys, `network.toml`, name (§3.13). Bind the ceremony socket.
2. Every `FOUNDER_INTERVAL_S` broadcast the own founder (and, once proposed, the own seal) to every `broadcast_targets()` address. Collect founders keyed by `pubkey` (latest wins; self included), seal proposals keyed by proposer (never our own) and endorsements from listed founder ids. The screen lists each founder as `name  pubkey[:8]` and flags `params MISMATCH`. Also keep `names[pubkey][name] = last seen`: a key with two names seen within `ONLINE_WINDOW_S` is flagged (L56).
3. Judge each proposal against our founders, again on every new founder or seal (L54): `waiting` (a listed key not heard, or under another name), `refused` (`seal_problem` on its list, a different recomputed genesis hash, an unlisted laptop we hear, or a key under two names), `ok` (everything matches). Print the proposer, the founder list, the short code and the notes whenever the judgement changes; with fewer than 4 founders also the f = 0 warning.
4. Input at the main prompt: `y` accepts the newest `ok` proposal (all `ok` proposals give the same genesis); an empty line or anything else proposes: `seal_problem` and the one-name check, then print the list, the short code and (f = 0) the warning, add `make_seal` to the datagrams re-sent every round, and ask `confirm`. `y` goes on; anything else withdraws the proposal and returns to the main prompt; end of input aborts (exit 4).
5. Build `g = parse_genesis(ceremony_genesis(...))` from the accepted or proposed list.
6. Broadcast `make_endorse` every `FOUNDER_INTERVAL_S` (founders and the proposal too, for slower laptops) until `check_endorsements` holds (unanimity: anyone can veto). An endorsement from a genesis node for a different hash → abort. No unanimity within `CEREMONY_TIMEOUT_S` after `y` → abort.
7. Write `genesis.json` (canonical JSON), `genesis.sha256`, `endorsements.json` (each via temp file + rename) and start the node (§3.13). Keep broadcasting the own endorse every `FOUNDER_INTERVAL_S` for `CEREMONY_TIMEOUT_S` so laptops that confirmed later can finish (L42). Stop the stdin reader first (L58).

### 3.11 `faults.py`

```python
@dataclass
class Fault:
    mode: str | None = None          # None | inject | lie | collude | stall | crash | equivocate | bad-artifact
    patch: str | None = None         # inject
    hash: str | None = None          # collude
    def on_new_request(self) -> None                 # crash: os._exit(1)
    def attest_without_build(self) -> str | None     # lie: random hex; collude: self.hash; stall: "STALL"
    @property
    def corrupt_artifacts(self) -> bool              # bad-artifact
```

`equivocate` is handled in `Engine.attest`. Validation at startup: a fault flag without `--allow-faults` → exit 2 with a message; `inject` requires `--patch`; `collude` requires a 64-hex `--hash`.

### 3.12 `node.py`

```
matrix-node --genesis PATH --id NODE_ID --key PATH --listen HOST:PORT --data DIR
            [--advertise HOST:PORT] [--no-discovery]
            [--allow-faults] [--fault MODE] [--patch FILE] [--hash HEX]
```

- `--advertise HOST:PORT`: the address put in hellos (`<IPv4>:<port>`, same rule as hello check 1). Default: own LAN IP (`local_ip()`) with the `--listen` port.
- `--no-discovery`: no UDP socket, no hellos; peers are reached only through genesis `addr`. Used by the local integration harness (dev genesis has static addrs, and tests must not broadcast onto the LAN). A genesis node without `addr` is then unreachable.

Startup (refuse to start, exit 2, on any failure):

1. `load_genesis`; `me = g.node(id)`; `pubkey_hex(load_key(key)) == me.pubkey`.
2. Validate fault flags and `--advertise`.
3. `mkdir -p DATA/{work,logs,artifacts}`; open `Store(DATA/matrix.db)`.
4. `await cleanup_startup(env)`; `expire_artifacts`.
5. `book = AddressBook(g)`; `PeerClient(g, me, book)`; `await engine.recover()`.
6. Start the aiohttp site (`make_app(..., book)`), `build_worker`, `sync_loop` and, unless `--no-discovery`, `Discovery(g, me, sk, book, listen_port, advertise).run()` (a bind failure refuses to start). Run until SIGINT/SIGTERM, then cancel tasks and close the session.

`run(args)` is the coroutine behind `main`; `matrix up` calls it in its own event loop (§3.13). With a ceremony genesis the book is still empty during `recover()`, so its re-sends reach no one. That is harmless: peers pull this node's bundles in their next `sync_loop` round once its hello arrives (within `HELLO_INTERVAL_S`), and its own first round with cursors 0 is retried every `sync_interval_s`.

### 3.13 `cli.py`

Common flags: `--genesis PATH` (default `$MATRIX_GENESIS`, else `~/.matrix/genesis.json`); `--node HOST:PORT`, the local builder (default `$MATRIX_NODE`, else `127.0.0.1:7700`). Both are accepted before or after the command of `release`, `status`, `evidence`, `tui` and `verify`. Defaults live under `~/.matrix/` (§4.1): pin `genesis.sha256`, release key `keys/release.key`.

**Address resolution** (`release`, `status`, `evidence`, `tui`), over `http://`: if every genesis node has an `addr`, use those (dev genesis). Otherwise `GET http://<--node>/v1/peers` once, feed every hello into a fresh `AddressBook(g)` (`book.accept`, so each is re-verified against genesis and the highest seq per signer wins; forged or foreign hellos are dropped), and build `PeerClient(g, CLIENT, book)`. A node with neither a verified hello nor a genesis `addr` is unreachable. `release` and `tui` refresh the book every poll. A client counts a builder as online iff `now - seq / 1000 < ONLINE_WINDOW_S`, with `now` from the same `/v1/peers` reply (L41).

| Command | Behaviour | Exit |
|---|---|---|
| `keygen --out F` | §3.2 | 0 / 4 |
| `up [--name N] [--refound] [--advertise HOST:PORT] [--home DIR] [--allow-faults --fault MODE [--patch FILE] [--hash HEX]]` | Founding ceremony if needed, then the node in the same process (below) | 0 on SIGINT/SIGTERM, 4 on any failure |
| `release --repo URL --tag T --commit SHA [--key F] [--wait 600] [--out dist/] [--output NAME]` | RFC §7.11 steps 1–5 (below). `--key` defaults to `~/.matrix/keys/release.key` | 0, 2, 3, 4, 5 |
| `status ID` | Fetch the request from any builder (must hash to `ID`), fetch all bundles, union, `verdict`, print the per-builder table | 0 if not PENDING, 3 if PENDING, 4 on error |
| `verify FILE --cert C --repo URL --tag T [--commit SHA] [--genesis-sha256 HEX]` | RFC §7.11 verify steps 1–4. Pin defaults to `~/.matrix/genesis.sha256`. No pin → exit 4 | 0, 1, 2, 4 |
| `evidence [--since 1h]` | Query `/v1/evidence` on all builders, dedupe by `(kind, signer, request_id)`, print | 0 / 4 |
| `tui` | Start the Textual app polling `--node` (§3.14) | 0 |
| `help [COMMAND]` | The grouped command overview with exit codes, or one command's help (same as `COMMAND --help`). Bare `matrix` prints the overview to stderr | 0; bare `matrix` and an unknown COMMAND 4 |

`up` details (`--home DIR` defaults to `~/.matrix`; all paths below are under it):

1. `genesis.json` exists and no `--refound` → skip to step 4 after checking `file_genesis_hash(genesis.json) == genesis.sha256` and `check_endorsements(g, endorsements.json)`; a failure → exit 4.
2. Otherwise: `load_network("network.toml")` from the current directory (the repo checkout, identical on every laptop); name = `--name` or `default_name()`; create `keys/` (mode 0700), `keys/node.key` and `keys/release.key` (0600) if absent. Keys never leave the laptop. Validate fault flags (without `--allow-faults` → exit 4).
3. Run the ceremony (§3.10a steps 1–6). Abort → exit 4, nothing written. With `--refound`, once the new ceremony succeeded and before its files are written, the old `genesis.json`, `genesis.sha256`, `endorsements.json` and `data/` move to `old-<old short code>/`; old certificates still verify against the old pin.
4. Start the node with `node.run`: id = the genesis node whose pubkey is `keys/node.key`'s (none → exit 4), `--listen 0.0.0.0:7700`, `--data <home>/data`, `--key keys/node.key`, discovery on, `--advertise` and fault flags passed through (still inert without `--allow-faults`). After a fresh ceremony, a second task keeps broadcasting the own endorse (§3.10a step 6).

`release` details:

1. `body = {v:1, repo_url, commit, tag}`; `valid_request` or exit 4. `env = make_envelope("release", signer_id, body, sk, g)`. `signer_id` is the genesis signer whose pubkey matches the key; none → exit 4.
2. Submit until f+1 distinct operators accepted: walk the genesis nodes, online ones first (each group in genesis order), take the first node of each operator, and submit to them one by one until f+1 answered 202 (n = 4, f = 1: 2). With a static-addr genesis there is no online information: plain genesis order. Fewer than f+1 accepting operators after trying all → exit 4. One acceptance is not enough: it may be a faulty builder that drops the request (`_submit_quorum`).
3. Every `RELEASE_POLL_S`: fetch `/bundle` from **all** builders, union by `msg_id`, `v = verdict(env, union, g)`. Stop when not `PENDING` or `--wait` expires. If fewer than f+1 builders ever answered → exit 4.
4. `AGREED(h)`: for each signer whose result is `h` (in random order), `GET /v1/artifacts/h` (limit 64 MiB); accept the first whose `sha256 == h`. None → keep polling until `--wait` expires, then exit 3.
5. Write `dist/<NAME>` (`--output`, default: last path segment of the repo URL) and `dist/<NAME>.matrix.json` = `{v:1, genesis_hash, request: env, attestations: [envelopes of non-equivocating signers whose result is h]}` (canonical JSON). Print the table. Print a warning if any `DISAGREE` signer exists. Exit 0.

Mapping: `BUILD_FAILED` → 5, `NOT_REPRODUCIBLE` → 2, `PENDING` at timeout → 3, `INVALID` and errors → 4.

`verify` never opens a socket. Unreadable file, unreadable or invalid genesis, or a genesis whose hash differs from the pin → exit 4. Certificate that fails `parse_certificate` → exit 2.

### 3.14 `tui.py`

Textual `App` with four screens (RFC §7.12): Builders (`b`), Releases (`r`, `Enter` → Detail), Detail (`l` toggles the log tail), Evidence (`e`, `Enter` shows proof JSON). A `set_interval(1.0, refresh)` polls the local node at `--node`: `/v1/peers`, `/v1/requests?since=0`, `/v1/requests/{id}`, `/bundle`, `/v1/evidence`; and `/v1/health` of every reachable builder. The TUI runs `verdict()` locally on fetched data. It keeps no state beyond the last poll result and never opens the database.

- Builders screen, one row per genesis node: id, operator, address, online/offline and last seen from the verified hellos of `/v1/peers` (§3.13 address resolution; with a static-addr genesis, address from genesis and online = `/v1/health` answered), and genesis match (`/v1/health` `genesis_hash == g.hash`). Offline members stay listed: disconnect is not leave.
- Log tail (`l`): fetched only from `--node` (the laptop's own builder, a loopback address by default) and only for its own build; other builders answer 404 (§3.10). The local builder id is the `node_id` from `--node`'s `/v1/health` (display only).
- Forms (L59): `n` runs `cli.release_job` (the code of `matrix release`: every option is a field), `v` runs `cmd_verify`, `k` runs `cmd_keygen`. A `FormScreen` (Enter moves to the next field and runs on the last; Esc cancels; required fields are checked) starts one job at a time as an asyncio worker with stdout and stderr captured; a `ResultScreen` shows the output and the exit code. Defaults: repo from `allowed_repos[0]`, key and pin under the home dir (`matrix up --home`; `~/.matrix` for a standalone `matrix tui`). The Releases view shows the running release live. Not in the TUI: `status` (the Detail screen) and `evidence` (the Evidence screen) already are screens; `up` options (name, `--refound`, `--advertise`, faults) change the builder process, so they need a restart of `matrix up`.

## 4. Data formats

| Item | Format |
|---|---|
| Key file | 64 lowercase hex (Ed25519 seed) + optional `\n`, mode 0600 |
| Genesis pin | `~/.matrix/genesis.sha256`: 64 hex + optional `\n` |
| Envelope, certificate | Canonical JSON (§3.1), see [openapi.yaml](openapi.yaml) `components.schemas` |
| Data dir | `<data>/matrix.db`, `<data>/work/<rid>/`, `<data>/logs/<rid>.log`, `<data>/artifacts/<sha256>` |
| Container name | `mx-<node_id>-<rid[:8]>-<attempt>-<step>` with step ∈ {`deps`, `build`, `build-r`} |
| Endorsements | `~/.matrix/endorsements.json`: canonical JSON list of the n endorse envelopes (§4.3), sorted by `signer` |

### 4.1 `~/.matrix/` (written by `matrix up`; `--home` moves it)

```
~/.matrix/
  keys/node.key        builder key, 0600, generated locally, never leaves the laptop
  keys/release.key     release-signer key (id <name>-rel), 0600, same rules
  genesis.json         founded genesis, canonical JSON, no addr
  genesis.sha256       the pin: 64 hex = file_genesis_hash(genesis.json)
  endorsements.json    one endorsement per genesis node (§4.3)
  data/                the node's data dir (§4 table)
  old-<short code>/    previous network after --refound
```

Consumers get the pin through a trusted channel (the project README in the source repository, or the founders directly; never the release page alone, RFC A5) plus a copy of `genesis.json`.

### 4.2 `network.toml` (repo root, identical on every laptop)

```toml
[network]
name = "matrix-demo"                       # becomes network_id
allowed_repos = ["https://github.com/<org>/matrix-hello"]
allowed_images = { "go1.23" = "golang@sha256:<linux/amd64 digest>" }
allowed_goos = ["linux"]
allowed_goarch = ["amd64"]
build_timeout_s = 45
request_ttl_s = 3600
sync_interval_s = 5
```

Exactly these keys, no others (§3.10a `load_network`). `params_hash = sha256_hex(canonical_json(<the [network] table>))`. `f`, `replicas`, `threshold`, `nodes` and `release_signers` come from the ceremony, not from this file.

### 4.3 UDP messages (port 7788, one canonical JSON object per datagram)

| Type | Signer | Body | Signed bytes | Max |
|---|---|---|---|---|
| `hello` | node id | `{genesis_hash, addr: "<IPv4>:<port>", seq: <int, unix ms>}` | `SIG_PREFIX + genesis_hash + b"\0" + canonical_json(unsigned)` | 512 |
| `founder` | node pubkey hex | `{network_id, id: <name>, pubkey, release_pubkey, release_sig, params_hash}` | `FOUNDER_PREFIX + network_id + b"\0" + canonical_json(unsigned)`, node key | 1024 |
| `endorse` | node id | `{genesis_hash}` | `SIG_PREFIX + genesis_hash + b"\0" + canonical_json(unsigned)` | 1024 |

Every message is `{"v": 1, "type", "signer", "body", "sig": <128 hex>}`, `unsigned = {v, type, signer, body}`. Example hello:

```json
{"body":{"addr":"172.20.10.3:7700","genesis_hash":"<64 hex>","seq":1793520000123},
 "sig":"<128 hex>","signer":"laptop-a","type":"hello","v":1}
```

Hellos are sent to `255.255.255.255:7788` every 5 s, at startup and on address change; replies to a new or changed address are unicast. Founder and endorse messages are broadcast every 2 s during the ceremony.

## 5. Startup recovery (`Engine.recover`)

For each request in `live_requests(now, ttl)`:

- `my_builds.result` set (attested) → re-broadcast own stored attestation(s). Never rebuild.
- Phase `RECEIVED` or `BUILDING`, selected, not attested → set `RECEIVED` (back in the persisted queue, oldest first).
- Others unchanged.

Then the first `sync_loop` round runs with all cursors at 0.

## 6. Phases

`RECEIVED → BUILDING → ATTESTED | MISSED`, `OBSERVING`. `SHED` is no longer written (L30) but stays a valid value. These are the only values written to `requests.phase`. Settlement is computed, not stored.

## 7. Concurrency model

One process per builder, one event loop, four long-lived tasks: aiohttp server, `build_worker`, `sync_loop`, `Discovery.run` (absent with `--no-discovery`). The address book is touched only from the loop thread, like the database. The database is touched only from the loop thread. Builds are subprocesses, so they never block the loop. Broadcasts are fire-and-forget tasks kept in a set, so they are not garbage-collected.

## 8. Logging

`<ts> <node_id> <event> key=value ...`. Events: `request.new`, `request.queued`, `build.start`, `build.outcome kind=… reason=…`, `attest.sent result=…`, `attest.recv signer=…`, `evidence kind=… signer=…`, `sync.peer_error peer=…`, `hello.reject reason=size|parse|signer|genesis|replay|sig from=<ip>` (DEBUG, so a flood cannot fill the log), `hello.send_error err=…` (DEBUG), `peer.online node=… addr=…`, `peer.addr node=… addr=…`, `peer.offline node=…`. Ceremony (printed by `matrix up`): `founder.seen id=… fp=…`, `founder.mismatch id=…`, `seal.refused reason=…`, `endorse.recv signer=…`, `ceremony.abort reason=mismatch|timeout|declined`.

## 9. Error handling summary

| Situation | Behaviour |
|---|---|
| Invalid input over HTTP | 4xx, logged at DEBUG, never an exception trace |
| Peer unreachable | Ignored; retried next sync |
| Build exception (bug) | Caught in the worker, logged with traceback, outcome `ERROR`; the worker keeps running |
| SQLite error | Crash the process (restart recovery handles it) |
| Invalid, foreign, replayed or forged UDP datagram | Dropped silently (`hello.reject` at DEBUG); never raises |
| UDP bind fails at startup | Refuse to start (exit 2); `--no-discovery` runs without it |
| UDP send fails, or no local IP (Wi-Fi off) | Logged at DEBUG, retried next round; the node keeps running; peers see it offline after 15 s |
| Peer has no verified hello and no genesis `addr` | Unreachable: pushes skipped, reads return `None`; pull sync catches up once its hello arrives |
| Own clock jumped back across a restart | Peers drop its hellos (check 4) until the clock passes the last seq they accepted; liveness only |
| `/v1/peers` unreachable from the CLI | Only genesis `addr`s are used; nodes without one are unreachable; usual exit codes apply |
| Ceremony: missing or invalid `network.toml`, declined code, mismatching endorsement, `CEREMONY_TIMEOUT_S` | Exit 4, nothing written |

## 10. Decisions added by this LLD

These fill gaps the RFC leaves open. Each one is the simplest option that works.

| # | Decision |
|---|---|
| L1 | Key file = hex seed; genesis pin = canonical genesis hash in `~/.matrix/genesis.sha256` |
| L2 | `X-Matrix-From` header is a non-trusted hint for fetching unknown requests; otherwise 409 and wait for pull sync |
| L3 | `GET /v1/requests` items also carry `received_at`, so pull sync can skip requests older than the TTL on the peer's clock |
| L4 | Builders explicitly fetch the requested tag (`git fetch ... refs/tags/<tag>`), because `clone` does not fetch tags outside branch history |
| L5 | SQLite is used synchronously from the event-loop thread only (the RFC's single writer) |
| L6 | `release --output NAME` sets the artifact file name (default: repo name), because the CLI does not read `matrix.toml` |
| L7 | Extra error codes: 409 `unknown_request` / `expired` on `POST /v1/messages`, 413 for oversized bodies |
| L8 | `lie`, `collude` and `stall` skip the build entirely |
| L9 | CLI genesis path from `--genesis`, then `$MATRIX_GENESIS`, then `~/.matrix/genesis.json` |
| L10 | Requests dequeued after settlement are not built (phase `MISSED`, reason `settled`) |
| L11 | `ruff` (lint + format, line length 100) is the only extra dev tool |
| L12 | Deterministic test keys: seed = `sha256(b"matrix-test:" + id)`; golden vectors in `tests/vectors/` |
| L13 | Real genesis keys are generated on each laptop with `matrix keygen`; only public keys are collected (for the laptop network, superseded by the ceremony, L33) |
| L14 | `SIG_PREFIX` is defined in `crypto.py` (it signs, and `model` imports `crypto`); `model.SIG_PREFIX` re-exports it |
| L15 | `Engine.on_request` returns 403 when the signer is not a release signer **or** `repo_url` is not in `allowed_repos` (RFC §7.9 / openapi), 400 for other invalid envelopes. LLD §3.9 step 1 only named the signer case |
| L16 | `Engine.fault` is a public attribute; `net` reads `engine.fault.corrupt_artifacts` for `bad-artifact` (`make_app` has no fault parameter) |
| L17 | `Engine.on_request` also returns 413 for a body over 4096 bytes (same as `on_attest` over 1024); `net` enforces the limit too |
| L20 | The development genesis generator refuses to overwrite existing private keys; reruns require a fresh output directory. |
| L21 | Invalid `since` query values on read-only listing routes use the default cursor 0. |
| L22 | `build(..., patch=...)` takes a **file path** (the `--patch FILE` of the `inject` fault), applied with `git apply -- <absolute path>` after checkout and before the recipe is read |
| L23 | `matrix.toml` must be a regular file of at most 4 KiB (checked with `lstat`, so a symlink is never followed) or the outcome is `BAD_RECIPE`; the build output is opened with `O_NOFOLLOW` and a non-regular or oversized file is `ERROR` |
| L24 | The 512 MiB source-size cap is checked after checkout, not while cloning; the build timeout bounds a hostile clone. Each step keeps at most 1 MiB per output stream in memory and 1 MiB per request in `logs/<rid>.log` across all attempts |
| L25 | The confirming rerun of `go build` runs only when exit code is 1 and stderr has no environmental marker; `classify_go_build` returns `ERROR` for any other code, including 0. `ARTIFACT_RETENTION_S` lives in `builder.py` (`protocol.py` keeps an unused copy) |
| L26 | A truncated build stderr cannot prove a deterministic compile error: abstain (`ERROR`) rather than run a confirming build or attest `FAILED`. Artifact copies use private temporary files, and cancellation joins the copy before removing its work directory. |
| L27 | Peer HTTP JSON reads are capped at 1 MiB and reject duplicate keys or non-finite numbers; finite floating-point timestamps remain valid in unsigned API metadata. Signed envelopes still reject floats during validation. |
| L30 | **Adopted as RFC rev 5 §7.6 rule 2 (was a deviation from rev 4).** A selected builder never sheds: every request it must build stays in SQLite as `RECEIVED` and is built oldest first, also after a restart. The backlog is bounded by the ingest cap (20/min) and the TTL; requests that settle while queued cost no build (L31). |
| L31 | Before building, the worker pulls the request's bundle from every peer through the normal `on_attest` validation and re-runs `verdict()`. A request already settled by others (while queued, or while this node was offline) is marked `MISSED`/`settled` and not built. Peers' phases and verdicts are never trusted, only signed attestations. |
| L32 | **RFC rev 5.** Addresses are discovered by signed UDP hellos and `addr` is optional in genesis (replaces genesis addrs and tinc host files): transport was always untrusted, addresses do not affect security, and the network survives DHCP changes |
| L33 | **RFC rev 5.** Genesis is created by a unanimous founding ceremony with a human-compared short code (replaces hand-assembled genesis): no authority, every member signs for itself, anyone can veto |
| L34 | **RFC rev 5.** Disconnect is not leave: membership changes only by re-founding (epochs are future work), which stops the shrink-to-quorum attack; offline members only delay |
| L35 | **RFC rev 5.** Full-mesh push plus pull anti-entropy (D8, now explicit); no gossip membership and no DHT, whose open or partial views enable Sybil, eclipse and routing poisoning |
| L36 | **RFC rev 5.** tinc or WireGuard optional, plain LAN is the default (replaces the RFC §7.13 default): integrity comes from signatures; plain LAN loses only confidentiality |
| L37 | **RFC rev 5.** One builder per laptop: n = 4, f = 1, R = 4, T = 2 (replaces 8 builders, f = 2); still tolerates one malicious plus one offline builder. The 8-builder compose network stays for development |
| L38 | **RFC rev 5.** `GET /v1/requests/{id}/log` answers loopback callers only, 404 otherwise: logs reveal host details; requests, attestations and evidence stay public for verifiability |
| L39 | Founder and endorse datagrams are capped at `MAX_CEREMONY` = 1024 bytes, because a founder message (two pubkeys, a params hash, a signer pubkey and a signature) is about 600 bytes, over `MAX_HELLO` |
| L40 | A node stores its own latest hello in its address book, so `/v1/peers` lists itself; its echoed broadcast fails the replay check harmlessly |
| L41 | `/v1/peers` carries no receive times, so clients judge online as `now - seq/1000 < ONLINE_WINDOW_S` (serving node's clock vs the sender's ms clock); assumes laptop clocks within a few seconds (NTP). The node itself uses local receive time |
| L42 | Endorsements from listed founders are verified on arrival with the founder's key and the hash they carry, kept, and counted only if that hash is ours; after a fresh ceremony `matrix up` keeps broadcasting its endorse for `CEREMONY_TIMEOUT_S`, so the last laptop to confirm can finish. An endorsement of another hash from a genesis node aborts |
| L43 | `matrix up` reads `network.toml` from the current directory, takes `--home DIR` (default `~/.matrix`, used by the demo's rogue), aborts on any answer but `y`, maps every failure to exit 4, and on `--refound` moves the old network to `<home>/old-<short code>/` |
| L44 | Seal also requires that the built genesis passes `parse_genesis` and lists our own key; later `matrix up` runs check the pin and `endorsements.json` before starting |
| L45 | `--node HOST:PORT` (default `$MATRIX_NODE`, else `127.0.0.1:7700`) is the local builder for `release`, `status`, `evidence` and `tui`, replacing `tui --node NODE_ID`; the CLI calls `/v1/peers` only if some genesis node has no `addr` |
| L46 | The discovery socket binds `0.0.0.0:7788` with `SO_BROADCAST` and `SO_REUSEADDR`; a bind failure refuses start; the local harness runs nodes with `--no-discovery` and static addrs |
| L47 | Ceremony `release_signers` are sorted by their own `pubkey` (the release key), `nodes` by the node key |
| L48 | Every HTTP body (server POSTs and client downloads) is read to EOF in chunks with a cap (`net._read_capped`); `StreamReader.read(n)` returns as soon as *some* bytes arrived, which truncated multi-chunk artifacts so `release` never certified |
| L49 | The founder message carries `release_sig`, a signature by the release key over `founder_bytes(network_id, {pubkey, release_pubkey})`, so a founder cannot list someone else's release key as its own |
| L50 | `local_ip()` tries `255.255.255.255:7788`, then `192.0.2.1:9` (TEST-NET-1, follows the default route); loopback and `0.0.0.0` count as no address. UDP `connect` sends nothing |
| L51 | The CLI's `ClientBook` maps the local builder's genesis id (from `--node`'s `/v1/health`) to the `--node` address, so its loopback-only routes (the log) work; every other builder comes from verified hellos or genesis `addr`. `release` POSTs resolve through the same book |
| L52 | The ceremony takes an injected bus and `ask(kind)` (`"seal"` / `"confirm"`); production uses UDP and a daemon stdin thread (an interrupted ceremony never waits for Enter on exit); tests run four ceremonies in memory |
| L53 | **RFC rev 5.** `f = 0` is allowed in `parse_genesis` (`f >= 0`, other integers `>= 1`) and `max(per-operator nodes) <= max(f, 1)`, so `matrix up` can found a 2 or 3 laptop test network (T = 1: one builder certifies). The ceremony minimum is 2 founders and it prints a warning for f = 0. Frozen contract changed on purpose: needs Track A approval |
| L54 | The ceremony adds the signed `seal` proposal (founder prefix, `MAX_SEAL` = 2048 bytes: a seal lists name and key of every founder, about 140 bytes each). One laptop proposes, the others accept with `y`; a receiver re-judges each proposal on every founder or seal arrival, so loss and reordering only delay. Founding still needs every founder's endorsement of one exact hash. No explicit refusal message: not endorsing is the veto |
| L55 | `broadcast_targets()` sends hellos and ceremony datagrams to `255.255.255.255` and to each interface's own broadcast address (`SIOCGIFBRDADDR` ioctl on Linux and macOS; elsewhere only the limited broadcast): the limited broadcast leaves by the default route only, and some networks drop it but forward the directed one |
| L56 | A key announcing two names within `ONLINE_WINDOW_S` blocks proposing and accepting and is flagged on screen: two `matrix up` processes on one laptop made the latest-wins name flip, so laptops sealed different genesis files |
| L57 | `-v` / `--verbose` on every command (and `matrix-node`) sets the root logger to DEBUG on stderr (`~/.matrix/verbose.log` for `tui`): every step, UDP datagram, HTTP call and Docker command is logged under `matrix.cli`, `matrix.discovery`, `matrix.net`, `matrix.builder`, `matrix.node`. Without it nothing changes, except a one-time warning when no other laptop is heard during the ceremony |
| L58 | After a fresh founding on a TTY, `_up` runs the node and the dashboard in one event loop (`cli._node_and_tui`): wait until `127.0.0.1:7700` answers (so the first frame is not "no builder"), play the curses intro, run `MatrixTui.run_async()`. A node that stops closes the dashboard; quitting the dashboard leaves the node in the foreground. The ceremony's stdin reader thread (`select` + `os.read`, stoppable) is stopped when the ceremony ends, because the dashboard reads the same stdin; `--verbose` logging moves to `<home>/verbose.log` while the dashboard is open. Later runs of `matrix up` are unchanged |
| L59 | The TUI gets forms for `release`, `verify` and `keygen` (RFC §7.12 had it read-only). They call the same functions as the CLI (`release_job` was split out of `cmd_release`), with output captured by `contextlib.redirect_stdout/stderr`; because that is process-wide only one form job runs at a time |

## 11. Tests

| File | Asserts |
|---|---|
| `tests/test_canon.py` | Key order and separators stable; floats rejected; duplicate keys → `None` |
| `tests/test_crypto.py` | Sign/verify round-trip; wrong genesis hash fails (replay); tampered body fails; garbage never raises |
| `tests/test_genesis.py` | Every startup rule in §3.3 rejects a bad file; demo and full genesis load; nodes with and without `addr` load (`addr is None`), a bad `addr` or an extra node key is rejected |
| `tests/test_model.py` | Request, recipe, ldflags, envelope and certificate strict parsing: wrong types, extra or missing keys, bad formats, oversize |
| `tests/test_select.py` | Deterministic; R = n returns every node |
| `tests/test_verdict.py` | One case per row of RFC §6.4, plus INVALID request, equivocator dropped, foreign `request_id` ignored, non-selected signer ignored |
| `tests/test_verdict_modelcheck.py` | RFC §9.1 model check. With R = n selection is symmetric, so fix malicious = last k nodes, k ∈ {0,1,2}. Pre-sign envelopes once and cache them. Assert (a), (b) and (c). |
| `tests/test_fuzz.py` | 10k random mutations of valid envelopes and certificates through `parse_envelope`, `parse_certificate`, `verdict`; nothing raises |
| `tests/test_builder_classify.py` | `classify_go_build` table; not-found marker mapping |
| `tests/test_protocol.py` | `Engine` with a fake `build` and fake `PeerClient`: requests queue in order (never shed), settled requests are not built, persist-before-broadcast, restart re-sends without rebuilding, evidence kinds |
| `tests/test_verify.py` | Wrong genesis, unsigned request, wrong repo, wrong tag, wrong commit, too few attestations, swapped file → correct exit codes |
| `tests/test_discovery.py` | Hello round-trip; each receiver check rejects in order: over 512 bytes, duplicate keys, extra or missing keys, wrong `type`, bad `addr` or `seq`, unknown signer, foreign `genesis_hash`, replay (`seq` equal or lower), bad signature; a stranger's key is rejected before signature work; random mutations never raise. `AddressBook`: `update` reports new or changed address, highest seq wins, online exactly within 15 s on an injected clock, `hellos()` latest per node. `Discovery` with a fake transport: fresh seq per hello, own hello in the book, unicast reply on a new address, `--advertise` used verbatim |
| `tests/test_up.py`, `tests/test_discovery.py` | `load_network` exact keys and types; `params_hash` stable; `parse_founder` rejects wrong network, `signer != pubkey`, bad self-signature, bad name, oversize; deterministic genesis: same founders in any arrival order → byte-identical canonical genesis and hash, f = n // 4, sorted nodes and signers, no `addr`; `short_code` format; proposing refused with < 2 founders, duplicate ids, a key under two names or a params mismatch; 2 founders give f = 0 and a warning; `parse_seal` rejects an unlisted proposer, unsorted founders, a changed body, another network, oversize; other laptops accept one proposal, also with 5 seals lost; a proposal before its founder waits, then shows; unanimity: n − 1 endorsements not active, n active; an endorsement for another hash aborts; timeout aborts and writes nothing (fake sockets, injected clock); `broadcast_targets` starts with the limited broadcast, unique IPv4 entries, announce sends to every target |
| `tests/test_net.py` | Every route and status code in openapi.yaml, plus `/v1/peers` and the log route returning 404 to a non-loopback caller; `PeerClient` prefers the book address over genesis `addr` and skips a node with neither |
| `tests/test_cli.py` | `release`, `status`, `evidence` against a test server; address resolution via `/v1/peers` drops forged or foreign hellos; `release` keeps submitting until f+1 distinct operators accepted, online first, else exit 4; `up` with fake sockets: ceremony then node start, later run skips the ceremony, pin mismatch → 4 |
| `tests/integration/test_matrix.py` (marked `integration`) | 8 local builders (f = 2, as before) and 4 local builders (`--nodes 4 --addrs local`, demo profile, `--no-discovery`), real Docker, RFC §9.1 fault matrix for f = 1: each fault mode on one builder still gives the honest verdict; 1 faulty + 1 offline certifies; 3 offline stays `PENDING` |

Run with `pytest -q` (unit) and `pytest -q -m integration` (needs Docker and network).

## 12. Development environment

### 12.1 `scripts/dev_genesis.py`

```
python scripts/dev_genesis.py --out dev --addrs compose|local --profile demo|full \
    --repo https://github.com/<org>/<repo> [--repo ...] \
    --image golang@sha256:<linux/amd64 digest>
```

It writes `dev/genesis.json`, `dev/genesis.sha256`, `dev/keys/builder1..8.key` and `dev/keys/release.key` (signer id `ci-release`). Operators are `laptopA..D`, two builders each. Addresses: `compose` → `builderN:7700`; `local` → `127.0.0.1:770(N-1)`. Profiles: `demo` = `build_timeout_s 45, sync_interval_s 5`; `full` = `150, 10`; both `request_ttl_s 3600`.

Dev genesis keeps **static `addr`s**: it is for development and rehearsal on one machine, not for the laptop network (that genesis comes from `matrix up`, §3.13). `--nodes 4` gives a 4-builder profile matching the laptop network (`builder1..4`, one per operator `laptopA..D`, f = 1, replicas 4, threshold 2); the default stays 8 builders, f = 2.

The local integration harness (`tests/integration/harness.py`) starts every node with `--no-discovery`, so tests use only the static addrs and never broadcast onto the LAN.

To get the single-platform digest: `docker buildx imagetools inspect golang:1.23` and copy the `linux/amd64` manifest digest (not the index digest).

### 12.2 Docker Compose

[docker-compose.yml](../docker-compose.yml) runs the demo network on one machine: builder1..4 (one per operator `laptopA..D`, from a `dev_genesis.py --nodes 4` genesis) from one image built by [Dockerfile](../Dockerfile) (Python 3.11 + git + the Docker CLI). The 8-builder dev genesis (the script's default) is for the integration tests only; compose has no services for builder5..8.

- Builders start build containers on the **host** daemon through `/var/run/docker.sock`. Bind-mount paths are resolved on the host, so the data directory is mounted at the **same absolute path** inside and outside (`MATRIX_DATA` in `.env`).
- Containers run as `MATRIX_UID:MATRIX_GID` with the host `docker` group added, so `--user <uid>:<gid>` and `rm -rf work/<id>` behave as on a laptop.
- The `cli` service (profile `tools`) runs `matrix` inside the compose network, where `builderN:7700` resolves; pass `--node builder1:7700`. The log tail is loopback-only, so the TUI there shows no logs (use `docker compose logs` or the data dir).
- [docker-compose.faults.yml](../docker-compose.faults.yml) holds the demo faults: builder3 `inject` (scene 3) and builder2 `equivocate` (scene 7). Restart one named builder with it at a time (f = 1).

Mounting the Docker socket gives root-equivalent access to the host. This is for development only.
