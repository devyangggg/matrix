"""Hardened, reproducible Go build (RFC §7.10, LLD §3.8).

Every subprocess is started from an argument list. Only a deterministic, rerun-confirmed compile
error is `FAILED`; everything environmental is `ERROR` and abstains (invariant 6).
"""

import asyncio
import contextlib
import hashlib
import os
import re
import shutil
import signal
import stat
from dataclasses import dataclass

from .genesis import Genesis
from .model import Request, parse_recipe

MAX_ARTIFACT = 64 * 1024 * 1024
MAX_SOURCE = (
    512 * 1024 * 1024
)  # shortcut: checked after checkout, not during; the timeout bounds it
MIN_FREE_DISK = 2 * 1024**3
MAX_LOG = 1024 * 1024
ARTIFACT_RETENTION_S = 86400
KILL_GRACE_S = 5
_CHUNK = 64 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)

# Step 1b/1c failures containing one of these mean the ref does not exist: BAD_REF, no retry.
NOT_FOUND_MARKERS = (
    "couldn't find remote ref",
    "did not match any",
    "reference is not a tree",
    "unknown revision",
    "not our ref",
)
# go build exit 1 with one of these means the host starved the compiler, not a compile error.
ENV_MARKERS = (
    "signal: killed",
    "cannot allocate memory",
    "no space left on device",
    "resource temporarily unavailable",
)


@dataclass(frozen=True)
class BuildEnv:
    data_dir: str  # <data>; work/, logs/, artifacts/ live under it
    node_id: str
    uid: int
    gid: int


@dataclass(frozen=True)
class Outcome:
    kind: str  # HASH | FAILED | ERROR | BAD_REF | BAD_RECIPE
    result: str | None  # sha256 hex for HASH, "FAILED" for FAILED, else None
    artifact_path: str | None
    reason: str  # short human-readable reason, stored in my_builds.error


class _Stop(Exception):
    def __init__(self, kind: str, reason: str):
        super().__init__(reason)
        self.outcome = Outcome(kind, None, None, reason)


# --- pure helpers ---------------------------------------------------------------------------


def classify_go_build(
    rc: int, stderr: str, rerun_rc: int | None, rerun_stderr: str | None, workdir: str
) -> str:
    """`FAILED` only for a compile error that a rerun reproduces byte for byte; else `ERROR`."""
    if rc != 1:  # 0 is not a failure; 125-127 are Docker, 137 is the OOM killer
        return "ERROR"
    low = stderr.lower()
    if any(m in low for m in ENV_MARKERS):
        return "ERROR"
    if rerun_rc != 1 or rerun_stderr is None:
        return "ERROR"
    if rerun_stderr.replace(workdir, "") != stderr.replace(workdir, ""):
        return "ERROR"
    return "FAILED"


def is_not_found(stderr: str) -> bool:
    low = stderr.lower()
    return any(m in low for m in NOT_FOUND_MARKERS)


def container_name(env: BuildEnv, rid: str, attempt: int, step: str) -> str:
    return f"mx-{env.node_id}-{rid[:8]}-{attempt}-{step}"  # step: deps | build | build-r


def docker_common(env: BuildEnv, rid: str, attempt: int, step: str) -> list[str]:
    """Sandbox flags shared by every build container (AGENTS §13.2 rule 9). Not optional."""
    return [
        "--rm",
        "--platform", "linux/amd64",
        "--user", f"{env.uid}:{env.gid}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--memory", "2g",
        "--cpus", "1",
        "--pids-limit", "512",
        "--name", container_name(env, rid, attempt, step),
        "-e", "HOME=/tmp",
        "-e", "GOTOOLCHAIN=local",
        "-e", "GOFLAGS=-mod=readonly -modcacherw",  # one argv element
    ]  # fmt: skip


def deps_argv(common: list[str], work: str, image: str) -> list[str]:
    """Step 2: network on, source read-only. Explicit proxy, no `direct`, so no VCS tool runs."""
    return [
        "docker", "run", *common,
        "-v", f"{work}/src:/src:ro",
        "-v", f"{work}/gomod:/go/pkg/mod",
        "-w", "/src",
        "-e", "GOPROXY=https://proxy.golang.org",
        "-e", "GOSUMDB=sum.golang.org",
        image, "go", "mod", "download",
    ]  # fmt: skip


def build_argv(common: list[str], work: str, image: str, recipe) -> list[str]:
    """Step 3: network off, source and module cache read-only."""
    return [
        "docker", "run", *common,
        "--network", "none",
        "-v", f"{work}/src:/src:ro",
        "-v", f"{work}/gomod:/go/pkg/mod:ro",
        "-v", f"{work}/out:/out",
        "-e", "CGO_ENABLED=0",
        "-e", f"GOOS={recipe.goos}",
        "-e", f"GOARCH={recipe.goarch}",
        "-e", "GOPROXY=off",
        "-e", "GOCACHE=/tmp/gocache",
        "-w", "/src",
        image, "go", "build", "-trimpath", "-buildvcs=false",
        "-ldflags", recipe.ldflags,  # one argv element, already allowlisted by parse_recipe
        "-o", f"/out/{recipe.output}", recipe.package,
    ]  # fmt: skip


# --- subprocesses ---------------------------------------------------------------------------


class _Log:
    """Build log under logs/<rid>.log, capped at MAX_LOG across all attempts."""

    def __init__(self, path: str, attempt: int):
        self.path = path
        self.used = 0 if attempt == 0 else (os.path.getsize(path) if os.path.exists(path) else 0)
        self.mode = "wb" if attempt == 0 else "ab"

    def write(self, data: bytes) -> None:
        room = MAX_LOG - self.used
        if room <= 0:
            return
        data = data[:room]
        with open(self.path, self.mode) as f:
            f.write(data)
        self.mode = "ab"
        self.used += len(data)


async def _drain(stream: asyncio.StreamReader, limit: int) -> bytes:
    """Read to EOF but keep only the first `limit` bytes, so hostile output cannot fill memory."""
    kept = bytearray()
    while chunk := await stream.read(_CHUNK):
        kept += chunk[: max(0, limit - len(kept))]
    return bytes(kept)


async def _quiet(*argv: str) -> bytes:
    """Best-effort helper command: never raises, never hangs."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return b""
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), 15)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.wait()
        return b""
    return out


async def _kill(proc: asyncio.subprocess.Process, container: str | None) -> None:
    """Stop a step: the whole process group, and the container (the `docker run` client dying
    does not stop it)."""
    if container:
        await _quiet("docker", "kill", container)
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), KILL_GRACE_S)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
            await proc.wait()
    if container:
        await _quiet("docker", "rm", "-f", container)


async def _run(
    argv: list[str], log: _Log, *, container: str | None = None, env: dict | None = None
) -> tuple[int, str, str]:
    """Run one step; return (rc, stdout, stderr). On cancellation or timeout, kill and re-raise."""
    log.write(b"$ " + " ".join(argv).encode("utf-8", "replace") + b"\n")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group, so the whole tree can be signalled
            env=env,
        )
    except OSError as e:  # git or docker is not installed
        raise _Stop("ERROR", f"cannot start {argv[0]}: {e.strerror}") from e
    assert proc.stdout is not None and proc.stderr is not None  # PIPE was requested
    finished = False
    try:
        out, err = await asyncio.gather(_drain(proc.stdout, MAX_LOG), _drain(proc.stderr, MAX_LOG))
        rc = await proc.wait()
        finished = True
    finally:
        if not finished:
            await _kill(proc, container)
    log.write(out + err)
    return rc, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


# --- build steps ----------------------------------------------------------------------------


def _tree_size(root: str) -> int:
    total = 0
    for dirpath, _, files in os.walk(root):  # os.walk does not follow symlinked dirs
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(dirpath, name)).st_size
    return total


async def _fetch_source(req: Request, work: str, log: _Log, patch: str | None) -> None:
    git_env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    src = f"{work}/src"

    async def git(*args: str) -> tuple[int, str, str]:
        return await _run(["git", *args], log, env=git_env)

    rc, _, err = await git("clone", "--filter=blob:none", "--no-checkout", "--", req.repo_url, src)
    if rc != 0:
        raise _Stop("ERROR", f"git clone failed: {err.strip()[:200]}")
    tag = req.tag
    steps = (
        ("fetch", ["-C", src, "fetch", "--no-tags", "origin", f"+refs/tags/{tag}:refs/tags/{tag}"]),
        ("checkout", ["-C", src, "checkout", "--detach", req.commit]),
    )
    for name, args in steps:
        rc, _, err = await git(*args)
        if rc != 0:
            kind = "BAD_REF" if is_not_found(err) else "ERROR"
            raise _Stop(kind, f"git {name} failed: {err.strip()[:200]}")

    rc, head, _ = await git("-C", src, "rev-parse", "HEAD")
    rc2, tagged, _ = await git("-C", src, "rev-parse", f"refs/tags/{tag}^{{commit}}")
    if rc != 0 or rc2 != 0 or head.strip() != req.commit or tagged.strip() != req.commit:
        raise _Stop("BAD_REF", "commit or tag does not resolve to the requested commit")

    if patch is not None:  # fault `inject` only
        rc, _, err = await git("-C", src, "apply", "--", os.path.abspath(patch))
        if rc != 0:
            raise _Stop("ERROR", f"git apply failed: {err.strip()[:200]}")
    if _tree_size(src) > MAX_SOURCE:
        raise _Stop("ERROR", "source tree exceeds 512 MiB")


def _read_recipe(src: str, g: Genesis):
    path = os.path.join(src, "matrix.toml")
    try:
        st = os.lstat(path)  # lstat: a symlinked matrix.toml must not read host files
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
            raise _Stop("BAD_RECIPE", "matrix.toml is not a small regular file")
        with open(path, "rb") as f:
            data = f.read(4097)
    except FileNotFoundError:
        raise _Stop("BAD_RECIPE", "matrix.toml is missing") from None
    recipe = parse_recipe(data, g)
    if recipe is None:
        raise _Stop("BAD_RECIPE", "matrix.toml is invalid")
    return recipe


def _store_artifact(src_file: str, artifacts: str) -> tuple[str, str]:
    """Hash while copying to artifacts/<hash>.tmp, fsync, rename, fsync the directory."""
    # O_NONBLOCK: opening a FIFO with no writer must not block a worker thread forever.
    fd = os.open(src_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise _Stop("ERROR", "output is not a regular file")
        if st.st_size > MAX_ARTIFACT:
            raise _Stop("ERROR", "output larger than 64 MiB")
        h, size = hashlib.sha256(), 0
        tmp = os.path.join(artifacts, f".tmp-{os.getpid()}-{os.path.basename(src_file)}")
        with open(tmp, "wb") as out:
            while chunk := f.read(_CHUNK):
                size += len(chunk)
                if size > MAX_ARTIFACT:
                    raise _Stop("ERROR", "output larger than 64 MiB")
                h.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
    digest = h.hexdigest()
    final = os.path.join(artifacts, digest)
    os.replace(tmp, final)
    dfd = os.open(artifacts, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return digest, final


async def build(
    req: Request, rid: str, g: Genesis, env: BuildEnv, attempt: int, patch: str | None = None
) -> Outcome:
    """One build attempt. The caller wraps this in `wait_for(..., build_timeout_s)`; on
    cancellation the running step is killed and CancelledError propagates."""
    if _HEX64.fullmatch(rid) is None:  # invariant 10: never join unvalidated input onto a path
        return Outcome("ERROR", None, None, "invalid request id")
    work = os.path.join(env.data_dir, "work", rid)
    logs = os.path.join(env.data_dir, "logs")
    artifacts = os.path.join(env.data_dir, "artifacts")
    try:
        # 0. preconditions and a clean slate
        os.makedirs(logs, exist_ok=True)
        os.makedirs(artifacts, exist_ok=True)
        if shutil.disk_usage(env.data_dir).free < MIN_FREE_DISK:
            return Outcome("ERROR", None, None, "less than 2 GiB of free disk")
        log = _Log(os.path.join(logs, f"{rid}.log"), attempt)
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(f"{work}/out")
        os.makedirs(f"{work}/gomod")
        names = [container_name(env, rid, attempt, s) for s in ("deps", "build", "build-r")]
        await _quiet("docker", "rm", "-f", *names)

        # 1. source and recipe
        await _fetch_source(req, work, log, patch)
        recipe = _read_recipe(f"{work}/src", g)
        image = g.allowed_images[recipe.image]

        # 2. dependencies: any failure here is environmental
        common = docker_common(env, rid, attempt, "deps")
        argv = deps_argv(common, work, image)
        rc, _, err = await _run(argv, log, container=names[0])
        if rc != 0:
            raise _Stop("ERROR", f"go mod download failed (rc={rc}): {err.strip()[:200]}")

        # 3. build, with a single confirming rerun for a compile error
        argv = build_argv(docker_common(env, rid, attempt, "build"), work, image, recipe)
        rc, _, err = await _run(argv, log, container=names[1])
        if rc != 0:
            rerun_rc = rerun_err = None
            if rc == 1 and not any(m in err.lower() for m in ENV_MARKERS):
                argv = build_argv(docker_common(env, rid, attempt, "build-r"), work, image, recipe)
                rerun_rc, _, rerun_err = await _run(argv, log, container=names[2])
            if classify_go_build(rc, err, rerun_rc, rerun_err, work) == "FAILED":
                return Outcome("FAILED", "FAILED", None, "deterministic compile error")
            raise _Stop("ERROR", f"go build failed (rc={rc}): {err.strip()[:200]}")

        # 4. hash and keep
        out_file = os.path.join(work, "out", recipe.output)
        try:
            digest, path = await asyncio.to_thread(_store_artifact, out_file, artifacts)
        except OSError as e:
            raise _Stop("ERROR", f"cannot read build output: {e.strerror}") from e
        return Outcome("HASH", digest, path, "ok")
    except _Stop as stop:
        return stop.outcome
    except OSError as e:  # work dir, log or artifact I/O
        return Outcome("ERROR", None, None, f"I/O error: {e}")
    finally:
        await asyncio.to_thread(shutil.rmtree, work, True)  # after every outcome, even a timeout


# --- node lifecycle -------------------------------------------------------------------------


async def cleanup_startup(env: BuildEnv) -> None:
    """Remove work dirs and containers left by a crashed run of this node."""
    work = os.path.join(env.data_dir, "work")
    with contextlib.suppress(OSError):
        for name in os.listdir(work):
            shutil.rmtree(os.path.join(work, name), ignore_errors=True)
    names = (await _quiet("docker", "ps", "-a", "--format", "{{.Names}}")).decode().split()
    mine = [n for n in names if n.startswith(f"mx-{env.node_id}-")]  # "-" stops builder1 vs 10
    if mine:
        await _quiet("docker", "rm", "-f", *mine)


def expire_artifacts(env: BuildEnv, now: float) -> None:
    """Delete outputs (and stray temp files) older than 24 h."""
    directory = os.path.join(env.data_dir, "artifacts")
    with contextlib.suppress(OSError), os.scandir(directory) as entries:
        for entry in entries:
            with contextlib.suppress(OSError):
                old = now - entry.stat(follow_symlinks=False).st_mtime > ARTIFACT_RETENTION_S
                if old and entry.is_file(follow_symlinks=False):
                    os.unlink(entry.path)
