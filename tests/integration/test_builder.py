"""Real git + real Docker builds of a throwaway local repo (B3, B4 acceptance).

Needs Docker and the pinned image already pulled:
    MATRIX_TEST_IMAGE=golang@sha256:<linux/amd64 digest> pytest -q -m integration tests/integration/test_builder.py
No network is needed for the repo (a local `file://` clone) or for dependencies (there are none).
Under gVisor (the daemon must have `runsc` registered): MATRIX_TEST_RUNTIME=runsc.
"""

import asyncio
import hashlib
import os
import pathlib
import platform
import shutil
import subprocess

import pytest

import matrix.builder as b
from matrix.builder import BuildEnv
from matrix.genesis import parse_genesis
from matrix.model import Request

pytestmark = pytest.mark.integration

IMAGE = os.environ.get("MATRIX_TEST_IMAGE", "")
RECIPE = """[build]
image = "go1.23"
package = "./cmd/hello"
goos = "linux"
goarch = "amd64"
ldflags = "-s -w -buildid= -X main.version=v1.2.0"
output = "hello"
"""
MAIN = 'package main\n\nimport "fmt"\n\nvar version = "dev"\n\nfunc main() { fmt.Println("hello from matrix " + version) }\n'
RID = "cd" * 32


@pytest.fixture(scope="module", autouse=True)
def _need_docker():
    if not IMAGE or shutil.which("docker") is None or shutil.which("git") is None:
        pytest.skip("set MATRIX_TEST_IMAGE and install docker and git")


@pytest.fixture
def g(genesis_dict):
    genesis_dict["allowed_images"] = {"go1.23": IMAGE}
    return parse_genesis(genesis_dict)


def git(repo, *args):
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    }  # fmt: skip
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True, env=env
    ).stdout.strip()


def make_repo(tmp_path, *, main=MAIN, recipe: str | None = RECIPE, tag="v1.2.0"):
    repo = tmp_path / "repo"
    (repo / "cmd" / "hello").mkdir(parents=True)
    (repo / "go.mod").write_text("module example.com/hello\n\ngo 1.23\n")
    (repo / "cmd" / "hello" / "main.go").write_text(main)
    if recipe is not None:
        (repo / "matrix.toml").write_text(recipe)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "release")
    git(repo, "tag", tag)
    return f"file://{repo}", git(repo, "rev-parse", "HEAD")


def env_in(tmp_path, name="data"):
    d = tmp_path / name
    d.mkdir(exist_ok=True)
    runtime = os.environ.get("MATRIX_TEST_RUNTIME") or None
    return BuildEnv(str(d), "builder1", os.getuid(), os.getgid(), runtime)


def sh(*argv, check=False) -> str:
    """Run a helper command (plain function, so async tests do not block-call subprocess)."""
    res = subprocess.run(argv, check=check, capture_output=True, text=True)
    return res.stdout


def containers(prefix="mx-builder1-"):
    out = sh("docker", "ps", "-a", "--format", "{{.Names}}")
    return [n for n in out.split() if n.startswith(prefix)]


def work_dirs(env):
    work = os.path.join(env.data_dir, "work")
    return os.listdir(work) if os.path.isdir(work) else []


async def test_honest_build_is_reproducible_across_independent_runs(tmp_path, g):
    url, commit = make_repo(tmp_path)
    req = Request(1, url, commit, "v1.2.0")
    first = await b.build(req, RID, g, env_in(tmp_path, "a"), 0)
    second = await b.build(req, RID, g, env_in(tmp_path, "b"), 0)
    assert first.artifact_path and first.kind == second.kind == "HASH", (first, second)
    assert first.result == second.result  # same bytes on independent work dirs
    assert (
        hashlib.sha256(pathlib.Path(first.artifact_path).read_bytes()).hexdigest() == first.result
    )
    assert work_dirs(env_in(tmp_path, "a")) == [] and containers() == []


@pytest.mark.skipif(platform.machine() != "x86_64", reason="runs the linux/amd64 output")
async def test_recipe_ldflags_reach_the_binary(tmp_path, g):
    url, commit = make_repo(tmp_path)
    out = await b.build(Request(1, url, commit, "v1.2.0"), RID, g, env_in(tmp_path), 0)
    assert out.kind == "HASH" and out.artifact_path
    binary = tmp_path / "hello"  # artifacts are plain files; make a runnable copy
    shutil.copy(out.artifact_path, binary)
    binary.chmod(0o755)
    assert sh(str(binary)).strip() == "hello from matrix v1.2.0"


async def test_compile_error_is_failed_after_a_confirming_rerun(tmp_path, g):
    url, commit = make_repo(tmp_path, main="package main\n\nfunc main() { undefined() }\n")
    env = env_in(tmp_path)
    out = await b.build(Request(1, url, commit, "v1.2.0"), RID, g, env, 0)
    assert (out.kind, out.result) == ("FAILED", "FAILED")
    assert work_dirs(env) == [] and containers() == []
    log = pathlib.Path(env.data_dir, "logs", f"{RID}.log").read_text()
    assert "undefined" in log and log.count("go build") >= 2  # build and the confirming rerun


async def test_missing_recipe_is_bad_recipe(tmp_path, g):
    url, commit = make_repo(tmp_path, recipe=None)
    out = await b.build(Request(1, url, commit, "v1.2.0"), RID, g, env_in(tmp_path), 0)
    assert out.kind == "BAD_RECIPE"


async def test_wrong_tag_or_commit_is_bad_ref(tmp_path, g):
    url, commit = make_repo(tmp_path)
    env = env_in(tmp_path)
    assert (await b.build(Request(1, url, commit, "v9.9.9"), RID, g, env, 0)).kind == "BAD_REF"
    # the tag exists but does not point at the requested commit (a moved tag)
    other = "2" * 40
    assert (await b.build(Request(1, url, other, "v1.2.0"), RID, g, env, 0)).kind == "BAD_REF"
    assert work_dirs(env) == []


async def test_unreachable_repo_is_an_error_not_a_vote(tmp_path, g):
    req = Request(1, f"file://{tmp_path}/does-not-exist", "1" * 40, "v1.2.0")
    out = await b.build(req, RID, g, env_in(tmp_path), 0)
    assert out.kind == "ERROR"


async def test_cancelling_a_running_build_leaves_no_container_and_no_work_dir(tmp_path, g):
    url, commit = make_repo(tmp_path)
    env = env_in(tmp_path)
    task = asyncio.create_task(b.build(Request(1, url, commit, "v1.2.0"), RID, g, env, 0))
    for _ in range(600):  # wait for a build container to exist, then pull the plug
        if containers() or task.done():
            break
        await asyncio.sleep(0.1)
    assert containers(), "no build container appeared"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert containers() == [] and work_dirs(env) == []


async def test_startup_cleanup_removes_only_this_nodes_stale_containers(tmp_path):
    env = env_in(tmp_path)
    os.makedirs(os.path.join(env.data_dir, "work", "stale", "src"))
    names = ["mx-builder1-aaaaaaaa-0-build", "mx-builder10-bbbbbbbb-0-build"]
    for n in names:
        sh("docker", "run", "-d", "--name", n, IMAGE, "sleep", "300", check=True)
    try:
        await b.cleanup_startup(env)
        assert containers("mx-builder1-") == []  # "-" keeps builder10 out of builder1's prefix
        assert names[1] in containers("mx-builder10-")  # another node's container survives
        assert work_dirs(env) == []
    finally:
        sh("docker", "rm", "-f", *names)
