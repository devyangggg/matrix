# Matrix — Low-Level Design

| | |
|---|---|
| **Source of truth** | [RFC-0001 rev 4](../Matrix_RFC_001.md). This LLD turns it into code-level contracts. If they disagree, the RFC wins: fix the LLD. |
| **Overview** | [HLD](HLD.md) |
| **HTTP contract** | [openapi.yaml](openapi.yaml) |

## 0. Conventions

- Python 3.11+, `asyncio` everywhere in the daemon. Type hints on every public function.
- Runtime dependencies: `pynacl`, `aiohttp`, `textual`. Dev: `pytest`, `pytest-asyncio`. **Nothing else.**
- Plain functions and frozen `@dataclass`es. Write a class only when it holds state (`Store`, `Engine`, `PeerClient`).
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
  store.py  builder.py  protocol.py  net.py  faults.py
  node.py   cli.py      tui.py
scripts/dev_genesis.py   # dev keys + genesis generator (§12)
tests/                   # §11
examples/faults/backdoor.patch
genesis.json  genesis.demo.json
Dockerfile  docker-compose.yml  docker-compose.faults.yml  .env.example
```

`pyproject.toml` optional dependency group `dev = ["pytest", "pytest-asyncio"]`.

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

`matrix keygen --out F` writes the seed hex to `F` with mode `0600` and prints the public key hex.

### 3.3 `genesis.py` (pure)

```python
@dataclass(frozen=True)
class Node:   id: str; operator: str; addr: str; pubkey: str      # addr "host:port"
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
- Every node has a non-empty `operator`; no operator has more than `f` nodes.
- `addr` matches `[A-Za-z0-9.-]+:[0-9]{1,5}`.
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
```

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
--rm --platform linux/amd64 --user <uid>:<gid> --cap-drop ALL
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

- `queue = asyncio.Queue(maxsize=1)`: the worker holds the request being built, the queue holds at most one more. `put_nowait` raising `QueueFull` → phase `SHED`.
- `ingest = collections.deque()`: timestamps of new requests in the last 60 s.
- `cursors: dict[node_id, float]`: pull-sync cursor per peer (peer's `now`).

**`on_request(raw)`**

1. `e = parse_envelope(raw, g)`. If `None`: 403 `forbidden` if `raw` is a dict whose `signer` is not a release signer, else 400 `invalid_envelope`. If `e.type != "release"` → 400.
2. `rid = request_id(e.body)`. Known → 202 `{id}` (idempotent, no forward).
3. Ingest cap: drop timestamps older than 60 s; if `len >= 20` → 429 `rate_limited`.
4. `fault.on_new_request()` (`crash` exits here).
5. Store with `t0 = now`, phase `RECEIVED` if `me.id in selected(...)` else `OBSERVING`. `peers.broadcast_request(e.raw)`.
6. If selected: `queue.put_nowait(rid)` or set phase `SHED`. Return 202 `{id}`.

**`build_worker()`** loops forever:

1. `rid = await queue.get()`. Skip (phase `MISSED`, reason `settled`) if `is_settled(rid)` or already attested.
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
def make_app(engine: Engine, store: Store, g: Genesis, me: Node, env: BuildEnv) -> web.Application
class PeerClient:
    def __init__(self, g: Genesis, me: Node)          # peers = every node except me
    async def broadcast_request(self, env: dict) -> None   # fire-and-forget tasks
    async def broadcast_attest(self, env: dict, only: list[str] | None = None) -> None
    async def get_json(self, node_id: str, path: str) -> Any | None   # None on any error
    async def get_bytes(self, node_id: str, path: str, limit: int) -> bytes | None
    async def close(self) -> None
```

- One `aiohttp.ClientSession` with `ClientTimeout(total=HTTP_TIMEOUT_S)`. Pushes add header `X-Matrix-From: <me.id>`. That header is only a hint for where to fetch an unknown request. It is never trusted.
- `web.Application(client_max_size=4096)`. Handlers read `await request.read()` and pass the bytes to the engine. Routes and payloads are in [openapi.yaml](openapi.yaml).
- Errors are `{"error": "<code>", "detail": "<text>"}` with codes `invalid_envelope`, `forbidden`, `too_large`, `rate_limited`, `unknown_request`, `expired`, `not_found`.
- `GET /v1/artifacts/{sha256}`: path param must match `[0-9a-f]{64}`, else 404. Look up the path with `store.artifact_path(sha)`; never join user input onto a path. Stream with `web.FileResponse`. If the fault is `bad-artifact`, return the bytes with the first byte XOR `0xFF`.
- `GET /v1/requests/{id}/log`: last 64 KiB of `logs/<id>.log` as `text/plain`, 404 if absent. `id` is validated as 64 hex first.
- Server binds to the `--listen` address (the tinc IP in the demo, `0.0.0.0` inside a container).

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
            [--allow-faults] [--fault MODE] [--patch FILE] [--hash HEX]
```

Startup (refuse to start, exit 2, on any failure):

1. `load_genesis`; `me = g.node(id)`; `pubkey_hex(load_key(key)) == me.pubkey`.
2. Validate fault flags.
3. `mkdir -p DATA/{work,logs,artifacts}`; open `Store(DATA/matrix.db)`.
4. `await cleanup_startup(env)`; `expire_artifacts`.
5. `await engine.recover()`.
6. Start the aiohttp site, `build_worker`, `sync_loop`. Run until SIGINT/SIGTERM, then cancel tasks and close the session.

### 3.13 `cli.py`

Common flags: `--genesis PATH` (default `$MATRIX_GENESIS`, else `~/.matrix/genesis.json`). Peers are the genesis node addresses, reached over `http://`.

| Command | Behaviour | Exit |
|---|---|---|
| `keygen --out F` | §3.2 | 0 / 4 |
| `release --repo URL --tag T --commit SHA --key F [--wait 600] [--out dist/] [--output NAME]` | RFC §7.11 steps 1–5 (below) | 0, 2, 3, 4, 5 |
| `status ID` | Fetch the request from any builder (must hash to `ID`), fetch all bundles, union, `verdict`, print the per-builder table | 0 if not PENDING, 3 if PENDING, 4 on error |
| `verify FILE --cert C --repo URL --tag T [--commit SHA] [--genesis-sha256 HEX]` | RFC §7.11 verify steps 1–4. Pin defaults to `~/.matrix/genesis.sha256`. No pin → exit 4 | 0, 1, 2, 4 |
| `evidence [--since 1h]` | Query `/v1/evidence` on all builders, dedupe by `(kind, signer, request_id)`, print | 0 / 4 |
| `tui [--node NODE_ID]` | Start the Textual app (default: first genesis node) | 0 |

`release` details:

1. `body = {v:1, repo_url, commit, tag}`; `valid_request` or exit 4. `env = make_envelope("release", signer_id, body, sk, g)`. `signer_id` is the genesis signer whose pubkey matches the key; none → exit 4.
2. Submit to the first node of each of the first 3 operators (genesis order). Fewer than 1 accepted (202) → exit 4.
3. Every `RELEASE_POLL_S`: fetch `/bundle` from **all** builders, union by `msg_id`, `v = verdict(env, union, g)`. Stop when not `PENDING` or `--wait` expires. If fewer than f+1 builders ever answered → exit 4.
4. `AGREED(h)`: for each signer whose result is `h` (in random order), `GET /v1/artifacts/h` (limit 64 MiB); accept the first whose `sha256 == h`. None → keep polling until `--wait` expires, then exit 3.
5. Write `dist/<NAME>` (`--output`, default: last path segment of the repo URL) and `dist/<NAME>.matrix.json` = `{v:1, genesis_hash, request: env, attestations: [envelopes of non-equivocating signers whose result is h]}` (canonical JSON). Print the table. Print a warning if any `DISAGREE` signer exists. Exit 0.

Mapping: `BUILD_FAILED` → 5, `NOT_REPRODUCIBLE` → 2, `PENDING` at timeout → 3, `INVALID` and errors → 4.

`verify` never opens a socket. Unreadable file, unreadable or invalid genesis, or a genesis whose hash differs from the pin → exit 4. Certificate that fails `parse_certificate` → exit 2.

### 3.14 `tui.py`

Textual `App` with four screens (RFC §7.12): Builders (`b`), Releases (`r`, `Enter` → Detail), Detail (`l` toggles the log tail), Evidence (`e`, `Enter` shows proof JSON). A `set_interval(1.0, refresh)` polls the chosen node: `/v1/requests?since=0`, `/v1/requests/{id}`, `/bundle`, `/v1/evidence`; and `/v1/health` of every node for the Builders screen. The TUI runs `verdict()` locally on fetched data. It keeps no state beyond the last poll result and never opens the database.

## 4. Data formats

| Item | Format |
|---|---|
| Key file | 64 lowercase hex (Ed25519 seed) + optional `\n`, mode 0600 |
| Genesis pin | `~/.matrix/genesis.sha256`: 64 hex + optional `\n` |
| Envelope, certificate | Canonical JSON (§3.1), see [openapi.yaml](openapi.yaml) `components.schemas` |
| Data dir | `<data>/matrix.db`, `<data>/work/<rid>/`, `<data>/logs/<rid>.log`, `<data>/artifacts/<sha256>` |
| Container name | `mx-<node_id>-<rid[:8]>-<attempt>-<step>` with step ∈ {`deps`, `build`, `build-r`} |

## 5. Startup recovery (`Engine.recover`)

For each request in `live_requests(now, ttl)`:

- `my_builds.result` set (attested) → re-broadcast own stored attestation(s). Never rebuild.
- Phase `RECEIVED` or `BUILDING`, selected, not attested → set `RECEIVED`, enqueue (overflow → `SHED`).
- Others unchanged.

Then the first `sync_loop` round runs with all cursors at 0.

## 6. Phases

`RECEIVED → BUILDING → ATTESTED | MISSED`, `RECEIVED → SHED`, `OBSERVING`. These are the only values written to `requests.phase`. Settlement is computed, not stored.

## 7. Concurrency model

One process per builder, one event loop, three long-lived tasks: aiohttp server, `build_worker`, `sync_loop`. The database is touched only from the loop thread. Builds are subprocesses, so they never block the loop. Broadcasts are fire-and-forget tasks kept in a set, so they are not garbage-collected.

## 8. Logging

`<ts> <node_id> <event> key=value ...`. Events: `request.new`, `request.shed`, `build.start`, `build.outcome kind=… reason=…`, `attest.sent result=…`, `attest.recv signer=…`, `evidence kind=… signer=…`, `sync.peer_error peer=…`.

## 9. Error handling summary

| Situation | Behaviour |
|---|---|
| Invalid input over HTTP | 4xx, logged at DEBUG, never an exception trace |
| Peer unreachable | Ignored; retried next sync |
| Build exception (bug) | Caught in the worker, logged with traceback, outcome `ERROR`; the worker keeps running |
| SQLite error | Crash the process (restart recovery handles it) |

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

## 11. Tests

| File | Asserts |
|---|---|
| `tests/test_canon.py` | Key order and separators stable; floats rejected; duplicate keys → `None` |
| `tests/test_crypto.py` | Sign/verify round-trip; wrong genesis hash fails (replay); tampered body fails; garbage never raises |
| `tests/test_genesis.py` | Every startup rule in §3.3 rejects a bad file; demo and full genesis load |
| `tests/test_model.py` | Request, recipe, ldflags, envelope and certificate strict parsing: wrong types, extra or missing keys, bad formats, oversize |
| `tests/test_select.py` | Deterministic; R = n returns every node |
| `tests/test_verdict.py` | One case per row of RFC §6.4, plus INVALID request, equivocator dropped, foreign `request_id` ignored, non-selected signer ignored |
| `tests/test_verdict_modelcheck.py` | RFC §9.1 model check. With R = n selection is symmetric, so fix malicious = last k nodes, k ∈ {0,1,2}. Pre-sign envelopes once and cache them. Assert (a), (b) and (c). |
| `tests/test_fuzz.py` | 10k random mutations of valid envelopes and certificates through `parse_envelope`, `parse_certificate`, `verdict`; nothing raises |
| `tests/test_builder_classify.py` | `classify_go_build` table; not-found marker mapping |
| `tests/test_protocol.py` | `Engine` with a fake `build` and fake `PeerClient`: shed on the third request, persist-before-broadcast, restart re-sends without rebuilding, evidence kinds |
| `tests/test_verify.py` | Wrong genesis, unsigned request, wrong repo, wrong tag, wrong commit, too few attestations, swapped file → correct exit codes |
| `tests/integration/test_matrix.py` (marked `integration`) | 8 local builders (`--addrs local`, demo profile), real Docker, RFC §9.1 fault matrix |

Run with `pytest -q` (unit) and `pytest -q -m integration` (needs Docker and network).

## 12. Development environment

### 12.1 `scripts/dev_genesis.py`

```
python scripts/dev_genesis.py --out dev --addrs compose|local --profile demo|full \
    --repo https://github.com/<org>/<repo> [--repo ...] \
    --image golang@sha256:<linux/amd64 digest>
```

It writes `dev/genesis.json`, `dev/genesis.sha256`, `dev/keys/builder1..8.key` and `dev/keys/release.key` (signer id `ci-release`). Operators are `laptopA..D`, two builders each. Addresses: `compose` → `builderN:7700`; `local` → `127.0.0.1:770(N-1)`. Profiles: `demo` = `build_timeout_s 45, sync_interval_s 5`; `full` = `150, 10`; both `request_ttl_s 3600`.

To get the single-platform digest: `docker buildx imagetools inspect golang:1.23` and copy the `linux/amd64` manifest digest (not the index digest).

### 12.2 Docker Compose

[docker-compose.yml](../docker-compose.yml) runs builder1..8 from one image built by [Dockerfile](../Dockerfile) (Python 3.11 + git + the Docker CLI).

- Builders start build containers on the **host** daemon through `/var/run/docker.sock`. Bind-mount paths are resolved on the host, so the data directory is mounted at the **same absolute path** inside and outside (`MATRIX_DATA` in `.env`).
- Containers run as `MATRIX_UID:MATRIX_GID` with the host `docker` group added, so `--user <uid>:<gid>` and `rm -rf work/<id>` behave as on a laptop.
- The `cli` service (profile `tools`) runs `matrix` inside the compose network, where `builderN:7700` resolves.
- [docker-compose.faults.yml](../docker-compose.faults.yml) is an override example that restarts chosen builders with fault flags for the demo scenes.

Mounting the Docker socket gives root-equivalent access to the host. This is for development only.
