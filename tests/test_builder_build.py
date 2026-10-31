"""`build()` and node lifecycle with scripted git/docker: no Docker, no network."""

import asyncio
import hashlib
import os
import pathlib
import sys
import time

import pytest

import matrix.builder as b
from matrix.builder import BuildEnv
from matrix.model import Request

RID = "ab" * 32
COMMIT = "1" * 40
REQ = Request(1, "https://github.com/org/hello", COMMIT, "v1.2.0")
RECIPE = b"""[build]
image = "go1.23"
package = "./cmd/hello"
goos = "linux"
goarch = "amd64"
ldflags = "-s -w"
output = "hello"
"""
COMPILE_ERR = "# hello\n./main.go:5:2: undefined: x\n"


class Script:
    """Stands in for matrix.builder._run: dispatches on the command and fakes its side effects."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.rc: dict[str, tuple[int, str, str]] = {}  # step -> canned (rc, stdout, stderr)
        self.builds: list[tuple[int, str, str]] = [(0, "", "")]  # successive `go build` results
        self.recipe: bytes | None = RECIPE
        self.head = self.tagged = COMMIT
        self.output = b"\x7fELF fake binary"
        self.hang: str | None = None  # step that blocks forever (to test timeouts)

    def step(self, argv: list[str]) -> str:
        if argv[0] == "git":
            if "rev-parse" in argv:
                return "head" if argv[-1] == "HEAD" else "tag"
            return next(a for a in argv if a in ("clone", "fetch", "checkout", "apply"))
        name = argv[argv.index("--name") + 1]
        return "build-r" if name.endswith("-build-r") else name.rsplit("-", 1)[1]

    async def __call__(self, argv, log, *, container=None, env=None):
        self.calls.append(argv)
        step = self.step(argv)
        if step == self.hang:
            await asyncio.sleep(3600)
        if step in self.rc:
            return self.rc[step]
        if step == "clone":
            src = argv[-1]
            os.makedirs(src)
            if self.recipe is not None:
                pathlib.Path(f"{src}/matrix.toml").write_bytes(self.recipe)
            return 0, "", ""
        if step == "head":
            return 0, self.head + "\n", ""
        if step == "tag":
            return 0, self.tagged + "\n", ""
        if step in ("build", "build-r"):
            res = self.builds.pop(0) if len(self.builds) > 1 else self.builds[0]
            if res[0] == 0:
                out = next(a for a in argv if a.endswith(":/out")).split(":")[0]
                pathlib.Path(f"{out}/hello").write_bytes(self.output)
            return res
        return 0, "", ""

    def steps(self) -> list[str]:
        return [self.step(c) for c in self.calls]


@pytest.fixture
def env(tmp_path):
    return BuildEnv(str(tmp_path), "builder1", os.getuid(), os.getgid())


@pytest.fixture
def script(monkeypatch):
    s = Script()
    monkeypatch.setattr(b, "_run", s)

    async def quiet(*argv):
        return b""

    monkeypatch.setattr(b, "_quiet", quiet)
    return s


def no_work_dir(env, rid=RID):
    return not os.path.exists(os.path.join(env.data_dir, "work", rid))


async def test_honest_build_returns_the_hash_and_keeps_the_artifact(genesis, env, script):
    out = await b.build(REQ, RID, genesis, env, 0)
    want = hashlib.sha256(script.output).hexdigest()
    assert (out.kind, out.result) == ("HASH", want)
    assert out.artifact_path == os.path.join(env.data_dir, "artifacts", want)
    assert pathlib.Path(out.artifact_path).read_bytes() == script.output
    assert script.steps() == ["clone", "fetch", "checkout", "head", "tag", "deps", "build"]
    assert no_work_dir(env)
    assert os.listdir(os.path.join(env.data_dir, "artifacts")) == [want]  # no temp file left


async def test_clone_failure_is_an_error_not_a_bad_ref(genesis, env, script):
    script.rc["clone"] = (128, "", "fatal: unable to access: Could not resolve host")
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and script.steps() == ["clone"] and no_work_dir(env)


@pytest.mark.parametrize(
    "step, stderr, kind",
    [
        ("fetch", "fatal: couldn't find remote ref refs/tags/v1.2.0", "BAD_REF"),
        ("fetch", "fatal: the remote end hung up unexpectedly", "ERROR"),
        ("checkout", "fatal: reference is not a tree: " + COMMIT, "BAD_REF"),
        ("checkout", "error: RPC failed; HTTP 503", "ERROR"),
    ],
)
async def test_ref_steps_map_not_found_to_bad_ref(genesis, env, script, step, stderr, kind):
    script.rc[step] = (1, "", stderr)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == kind and "deps" not in script.steps() and no_work_dir(env)


@pytest.mark.parametrize("field", ["head", "tagged"])
async def test_commit_or_tag_not_resolving_to_the_request_is_bad_ref(genesis, env, script, field):
    setattr(script, field, "2" * 40)  # e.g. the tag was moved after the request was signed
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "BAD_REF" and "deps" not in script.steps() and no_work_dir(env)


@pytest.mark.parametrize(
    "recipe",
    [
        None,
        b"not toml [",
        RECIPE.replace(b'"go1.23"', b'"go9"'),
        RECIPE.replace(b"-s -w", b"-extld=gcc"),
    ],
)
async def test_missing_or_invalid_recipe_is_bad_recipe(genesis, env, script, recipe):
    script.recipe = recipe
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "BAD_RECIPE" and "deps" not in script.steps() and no_work_dir(env)


async def test_symlinked_recipe_is_never_followed(genesis, env, script, tmp_path, monkeypatch):
    secret = tmp_path / "host-secret.toml"
    secret.write_bytes(RECIPE)  # a valid recipe, but outside the checkout
    orig = script.__call__

    async def with_symlink(argv, log, **kw):
        res = await orig(argv, log, **kw)
        if script.step(argv) == "clone":
            os.remove(f"{argv[-1]}/matrix.toml")
            os.symlink(secret, f"{argv[-1]}/matrix.toml")
        return res

    monkeypatch.setattr(b, "_run", with_symlink)
    assert (await b.build(REQ, RID, genesis, env, 0)).kind == "BAD_RECIPE"


async def test_oversized_source_tree_is_an_error(genesis, env, script, monkeypatch):
    monkeypatch.setattr(b, "MAX_SOURCE", 10)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and "deps" not in script.steps() and no_work_dir(env)


@pytest.mark.parametrize(
    "stderr", ["go: verifying module: checksum mismatch", "SECURITY ERROR\ngo.sum mismatch", ""]
)
async def test_dependency_failure_is_always_an_error_never_failed(genesis, env, script, stderr):
    script.rc["deps"] = (1, "", stderr)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and script.steps()[-1] == "deps" and no_work_dir(env)


async def test_confirmed_compile_error_is_failed(genesis, env, script):
    script.builds = [(1, "", COMPILE_ERR)]
    out = await b.build(REQ, RID, genesis, env, 0)
    assert (out.kind, out.result, out.artifact_path) == ("FAILED", "FAILED", None)
    assert script.steps()[-2:] == ["build", "build-r"]  # exactly one confirming rerun
    assert no_work_dir(env)


async def test_compile_error_that_does_not_reproduce_is_an_error(genesis, env, script):
    script.builds = [(1, "", COMPILE_ERR), (1, "", "different")]
    assert (await b.build(REQ, RID, genesis, env, 0)).kind == "ERROR"
    script.builds = [(1, "", COMPILE_ERR), (0, "", "")]  # the rerun succeeded: a flake
    assert (await b.build(REQ, RID, genesis, env, 0)).kind == "ERROR"


@pytest.mark.parametrize(
    "res",
    [
        (1, "", "go: signal: killed"),
        (1, "", "write: no space left on device"),
        (137, "", ""),
        (125, "", "docker: Error response from daemon"),
    ],
)
async def test_environmental_build_failures_abstain_without_a_rerun(genesis, env, script, res):
    script.builds = [res]
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and "build-r" not in script.steps() and no_work_dir(env)


async def test_output_over_64_mib_is_an_error_and_leaves_no_artifact(
    genesis, env, script, monkeypatch
):
    orig = script.__call__

    async def big(argv, log, **kw):
        res = await orig(argv, log, **kw)
        if script.step(argv) == "build":
            out = next(a for a in argv if a.endswith(":/out")).split(":")[0]
            os.truncate(f"{out}/hello", b.MAX_ARTIFACT + 1)  # sparse: instant
        return res

    monkeypatch.setattr(b, "_run", big)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and "64 MiB" in out.reason
    assert os.listdir(os.path.join(env.data_dir, "artifacts")) == []


async def test_low_disk_is_an_error_before_any_command_runs(genesis, env, script, monkeypatch):
    class Usage:
        free = b.MIN_FREE_DISK - 1

    monkeypatch.setattr(b.shutil, "disk_usage", lambda _: Usage)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and script.calls == []


@pytest.mark.parametrize("rid", ["../etc", "A" * 64, "ab" * 31, "ab" * 32 + "/x", ""])
async def test_request_id_is_validated_before_it_touches_a_path(genesis, env, script, rid):
    out = await b.build(REQ, rid, genesis, env, 0)
    assert out.kind == "ERROR" and script.calls == []
    assert not os.path.exists(os.path.join(env.data_dir, "work"))


async def test_inject_patch_is_applied_with_an_absolute_path(genesis, env, script, tmp_path):
    patch = tmp_path / "backdoor.patch"
    patch.write_text("")
    await b.build(REQ, RID, genesis, env, 0, patch=str(patch))
    (apply,) = [c for c in script.calls if "apply" in c]
    assert apply[-1] == str(patch) and apply[-2] == "--"
    script.calls.clear()
    await b.build(REQ, RID, genesis, env, 0)
    assert not any("apply" in c for c in script.calls)


async def test_failing_patch_is_an_error(genesis, env, script):
    script.rc["apply"] = (1, "", "error: patch failed")
    assert (await b.build(REQ, RID, genesis, env, 0, patch="/x.patch")).kind == "ERROR"


async def test_timeout_removes_the_work_dir_and_propagates(genesis, env, script):
    script.hang = "deps"
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(b.build(REQ, RID, genesis, env, 0), 0.2)
    assert no_work_dir(env)


def test_retry_attempts_append_to_one_capped_log(env, monkeypatch):
    log = b._Log(os.path.join(env.data_dir, "l.log"), 0)
    monkeypatch.setattr(b, "MAX_LOG", 10)
    log.write(b"123456")
    log2 = b._Log(os.path.join(env.data_dir, "l.log"), 1)  # a retry appends
    log2.write(b"abcdefgh")
    assert pathlib.Path(log.path).read_bytes() == b"123456abcd"  # capped at 10 bytes in total


# --- real subprocesses: killing, output caps -------------------------------------------------


async def test_cancelled_step_kills_its_whole_process_group(tmp_path, monkeypatch):
    killed = []

    async def quiet(*argv):
        killed.append(argv)
        return b""

    monkeypatch.setattr(b, "_quiet", quiet)
    pidfile = tmp_path / "pid"
    log = b._Log(str(tmp_path / "l.log"), 0)
    argv = ["sh", "-c", f"sleep 60 & echo $! > {pidfile}; wait"]
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(b._run(argv, log, container="mx-x-1-0-build"), 0.5)
    grandchild = int(pidfile.read_text())
    for _ in range(50):  # the grandchild is reparented and reaped asynchronously
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail("grandchild survived")
    # the container is killed explicitly: killing the `docker run` client would not stop it
    assert ("docker", "kill", "mx-x-1-0-build") in killed
    assert ("docker", "rm", "-f", "mx-x-1-0-build") in killed


async def test_step_output_is_capped_in_memory_and_in_the_log(tmp_path, monkeypatch):
    monkeypatch.setattr(b, "MAX_LOG", 100_000)
    log = b._Log(str(tmp_path / "l.log"), 0)
    code = "import sys; sys.stdout.write('x' * 3_000_000); sys.stderr.write('e' * 3_000_000)"
    rc, out, err = await b._run([sys.executable, "-c", code], log)
    assert rc == 0 and len(out) == len(err) == 100_000
    assert os.path.getsize(log.path) <= 100_000


async def test_missing_executable_is_an_error_not_a_crash(genesis, env, monkeypatch):
    async def quiet(*argv):
        return b""

    monkeypatch.setattr(b, "_quiet", quiet)
    monkeypatch.setenv("PATH", "/nonexistent")
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and no_work_dir(env)


# --- node lifecycle --------------------------------------------------------------------------


async def test_cleanup_startup_removes_only_this_nodes_leftovers(env, monkeypatch):
    for d in ("work/r1/src", "work/r2"):
        os.makedirs(os.path.join(env.data_dir, d))
    calls = []

    async def quiet(*argv):
        calls.append(argv)
        if argv[1] == "ps":
            names = (
                "mx-builder1-aaaa-0-build\nmx-builder10-bbbb-0-deps\nmx-builder1-cccc-1-deps\nweb"
            )
            return names.encode()
        return b""

    monkeypatch.setattr(b, "_quiet", quiet)
    await b.cleanup_startup(env)
    assert os.listdir(os.path.join(env.data_dir, "work")) == []
    rm = [c for c in calls if c[1] == "rm"]
    # builder10 and unrelated containers must survive
    assert rm == [("docker", "rm", "-f", "mx-builder1-aaaa-0-build", "mx-builder1-cccc-1-deps")]


async def test_cleanup_startup_without_work_dir_or_docker(env, monkeypatch):
    async def quiet(*argv):
        return b""  # docker unavailable

    monkeypatch.setattr(b, "_quiet", quiet)
    await b.cleanup_startup(env)  # must not raise


def test_expire_artifacts_keeps_fresh_files_and_ignores_symlinks(env, tmp_path):
    d = os.path.join(env.data_dir, "artifacts")
    os.makedirs(d)
    now = time.time()
    target = tmp_path / "precious"
    target.write_text("x")
    os.utime(target, (now - 10 * 86400, now - 10 * 86400))
    for name, age in (("old", 86400 + 60), ("fresh", 3600), ("edge", 86400 - 60)):
        path = os.path.join(d, name)
        open(path, "w").close()
        os.utime(path, (now - age, now - age))
    os.symlink(target, os.path.join(d, "link"))
    b.expire_artifacts(env, now)
    assert sorted(os.listdir(d)) == ["edge", "fresh", "link"]
    assert target.exists()


def test_expire_artifacts_without_a_directory_is_a_noop(env):
    b.expire_artifacts(env, time.time())


async def test_output_that_is_a_symlink_is_never_followed(
    genesis, env, script, monkeypatch, tmp_path
):
    secret = tmp_path / "host-file"
    secret.write_bytes(b"host data")
    orig = script.__call__

    async def link(argv, log, **kw):
        res = await orig(argv, log, **kw)
        if script.step(argv) == "build":
            out = next(a for a in argv if a.endswith(":/out")).split(":")[0]
            os.remove(f"{out}/hello")
            os.symlink(secret, f"{out}/hello")  # a build that tries to exfiltrate a host file
        return res

    monkeypatch.setattr(b, "_run", link)
    out = await b.build(REQ, RID, genesis, env, 0)
    assert out.kind == "ERROR" and os.listdir(os.path.join(env.data_dir, "artifacts")) == []


async def test_output_that_is_a_fifo_is_an_error_and_does_not_block(
    genesis, env, script, monkeypatch
):
    orig = script.__call__

    async def fifo(argv, log, **kw):
        res = await orig(argv, log, **kw)
        if script.step(argv) == "build":
            out = next(a for a in argv if a.endswith(":/out")).split(":")[0]
            os.remove(f"{out}/hello")
            os.mkfifo(f"{out}/hello")  # with no writer, a plain open() would block forever
        return res

    monkeypatch.setattr(b, "_run", fifo)
    out = await asyncio.wait_for(b.build(REQ, RID, genesis, env, 0), 5)
    assert out.kind == "ERROR" and "regular" in out.reason and no_work_dir(env)
    assert os.listdir(os.path.join(env.data_dir, "artifacts")) == []
