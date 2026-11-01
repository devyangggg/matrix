"""Pure builder logic: outcome classification, ref-error mapping, sandbox argv (RFC §7.10)."""

import itertools

import pytest

from matrix import builder
from matrix.builder import (
    BuildEnv,
    build_argv,
    classify_go_build,
    container_name,
    deps_argv,
    docker_common,
    is_not_found,
)
from matrix.model import Recipe

WORK = "/data/work/abc"
ENV = BuildEnv("/data", "builder3", 1234, 5678)
RID = "0123456789abcdef" * 4
ERR = f"# hello\n{WORK}/src/main.go:5:2: undefined: x\n"


@pytest.mark.parametrize(
    "rc, stderr, rerun_rc, rerun_stderr, want",
    [
        # a real compile error: exit 1, no environmental marker, the rerun fails identically
        (1, ERR, 1, ERR, "FAILED"),
        # the work-directory path is ignored when comparing
        (1, "x" + WORK + "y", 1, "xy", "FAILED"),
        # the rerun differs, did not fail, or never ran: environmental
        (1, ERR, 1, ERR + "more", "ERROR"),
        (1, ERR, 0, "", "ERROR"),
        (1, ERR, 2, ERR, "ERROR"),
        (1, ERR, None, None, "ERROR"),
        (1, ERR, 1, None, "ERROR"),
        # every environmental marker wins even when the rerun matches
        (1, "go: signal: killed", 1, "go: signal: killed", "ERROR"),
        (
            1,
            "fatal error: Cannot Allocate Memory",
            1,
            "fatal error: Cannot Allocate Memory",
            "ERROR",
        ),
        (1, "write: no space left on device", 1, "write: no space left on device", "ERROR"),
        (
            1,
            "fork: resource temporarily unavailable",
            1,
            "fork: resource temporarily unavailable",
            "ERROR",
        ),
        # Docker errors, the OOM killer, a signal or an unexpected code are never a vote
        (125, ERR, 125, ERR, "ERROR"),
        (126, ERR, 126, ERR, "ERROR"),
        (127, ERR, 127, ERR, "ERROR"),
        (137, "", 137, "", "ERROR"),
        (2, ERR, 2, ERR, "ERROR"),
        (-9, ERR, -9, ERR, "ERROR"),
        # success is not a failure and must never be classified FAILED
        (0, "", 0, "", "ERROR"),
    ],
)
def test_classify_go_build(rc, stderr, rerun_rc, rerun_stderr, want):
    assert classify_go_build(rc, stderr, rerun_rc, rerun_stderr, WORK) == want


@pytest.mark.parametrize(
    "stderr",
    [
        "fatal: couldn't find remote ref refs/tags/v9",
        "fatal: Couldn't find remote ref refs/tags/v9",  # git capitalises on some versions
        "error: pathspec 'x' did not match any file(s) known to git",
        "fatal: reference is not a tree: " + "a" * 40,
        "fatal: unknown revision or path not in the working tree",
        "error: upload-pack: not our ref " + "a" * 40,
    ],
)
def test_missing_ref_is_bad_ref(stderr):
    assert is_not_found(stderr)


@pytest.mark.parametrize(
    "stderr",
    [
        "fatal: unable to access 'https://github.com/': Could not resolve host: github.com",
        "fatal: the remote end hung up unexpectedly",
        "error: RPC failed; HTTP 503",
        "",
    ],
)
def test_network_errors_are_not_bad_ref(stderr):
    assert not is_not_found(stderr)


def test_container_names_are_unique_per_node_attempt_and_step():
    names = {container_name(ENV, RID, a, s) for a in range(3) for s in ("deps", "build", "build-r")}
    assert len(names) == 9
    assert container_name(ENV, RID, 1, "build") == "mx-builder3-01234567-1-build"
    other = BuildEnv("/data", "builder4", 1234, 5678)
    assert container_name(other, RID, 1, "build") != container_name(ENV, RID, 1, "build")


# --- sandbox flags (AGENTS §13.2 rule 9): removing any of these is a security regression -----

RECIPE = Recipe("go1.23", "./cmd/hello", "linux", "amd64", "-s -w -X main.v=1", "hello")
IMAGE = "golang@sha256:" + "a" * 64


def pairs(argv):
    return list(itertools.pairwise(argv))


def test_every_container_gets_the_hardening_flags():
    common = docker_common(ENV, RID, 0, "deps")
    assert "--rm" in common
    for flag in (
        ("--platform", "linux/amd64"),
        ("--user", "1234:5678"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--memory", "2g"),
        ("--cpus", "1"),
        ("--pids-limit", "512"),
        ("-e", "HOME=/tmp"),
        ("-e", "GOTOOLCHAIN=local"),
        ("-e", "GOFLAGS=-mod=readonly -modcacherw"),  # a single argv element
    ):
        assert flag in pairs(common), flag
    assert "--privileged" not in common and "--network" not in common


def test_dependency_step_has_network_but_read_only_source_and_no_direct_fallback():
    argv = deps_argv(docker_common(ENV, RID, 0, "deps"), WORK, IMAGE)
    assert "--network" not in argv  # needs the proxy
    assert ("-v", f"{WORK}/src:/src:ro") in pairs(argv)
    assert ("-e", "GOPROXY=https://proxy.golang.org") in pairs(argv)
    assert not any("direct" in a for a in argv)
    assert argv[-3:] == ["go", "mod", "download"] and IMAGE in argv


def test_build_step_is_offline_with_read_only_inputs_and_a_pinned_image():
    argv = build_argv(docker_common(ENV, RID, 0, "build"), WORK, IMAGE, RECIPE)
    assert ("--network", "none") in pairs(argv)
    assert ("-v", f"{WORK}/src:/src:ro") in pairs(argv)
    assert ("-v", f"{WORK}/gomod:/go/pkg/mod:ro") in pairs(argv)
    assert ("-v", f"{WORK}/out:/out") in pairs(argv)
    for env in ("CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOPROXY=off"):
        assert ("-e", env) in pairs(argv)
    assert argv.index(IMAGE) < argv.index("go")  # the image precedes the command
    assert ("-ldflags", "-s -w -X main.v=1") in pairs(argv)  # flags stay one element
    assert argv[-3:] == ["-o", "/out/hello", "./cmd/hello"] or argv[-2:] == [
        "/out/hello",
        "./cmd/hello",
    ]
    assert "-trimpath" in argv and "-buildvcs=false" in argv


def test_a_hostile_recipe_value_cannot_add_arguments():
    # parse_recipe already allowlists these; the argv builder must still keep each one atomic
    evil = Recipe("go1.23", "./x", "linux", "amd64", "-s; rm -rf /", "out --privileged")
    argv = build_argv(docker_common(ENV, RID, 0, "build"), WORK, IMAGE, evil)
    assert "--privileged" not in argv
    assert "-s; rm -rf /" in argv and "/out/out --privileged" in argv


def test_gvisor_runtime_flag_only_when_detected():
    assert "--runtime" not in docker_common(ENV, RID, 0, "build")
    gvisor = BuildEnv("/data", "builder3", 1234, 5678, "runsc")
    assert ("--runtime", "runsc") in pairs(docker_common(gvisor, RID, 0, "build"))


@pytest.mark.parametrize(
    "info, platform, runtime, text",
    [
        (b'{"runc":{},"runsc":{"path":"/usr/bin/runsc"}}\n', "linux", "runsc", "gVisor"),
        (b'{"runc":{}}\n', "darwin", None, "Docker Desktop's Linux VM"),
        (b'{"runc":{}}\n', "linux", None, "WARNING: gVisor not found"),
        (b"", "linux", None, "WARNING"),  # docker info failed: never claim isolation
    ],
)
async def test_isolation_reports_what_this_laptop_gets(monkeypatch, info, platform, runtime, text):
    async def quiet(*argv):
        return info

    monkeypatch.setattr(builder, "_quiet", quiet)
    monkeypatch.setattr(builder.sys, "platform", platform)
    got, how = await builder.isolation()
    assert got == runtime and text in how


async def test_verbose_streams_each_output_line_live_and_keeps_the_log(tmp_path, caplog):
    import logging
    import sys

    log = builder._Log(str(tmp_path / "x.log"), 0)
    argv = [
        sys.executable,
        "-c",
        "import sys; print('out1'); print('out2', end=''); sys.stderr.write('err1\\n')",
    ]
    with caplog.at_level(logging.DEBUG, logger="matrix.builder"):
        rc, *_ = await builder._run(argv, log, container="mx-test")
    lines = [r.getMessage() for r in caplog.records]
    assert (
        rc == 0 and "[mx-test] out1" in lines and "[mx-test] out2" in lines
    )  # unterminated tail too
    assert "[mx-test err] err1" in lines
    assert "out1" in (tmp_path / "x.log").read_text()  # the build log file is unchanged


async def test_output_is_not_echoed_without_verbose(tmp_path, caplog):
    import logging
    import sys

    log = builder._Log(str(tmp_path / "x.log"), 0)
    with caplog.at_level(logging.WARNING, logger="matrix.builder"):
        await builder._run([sys.executable, "-c", "print('quiet')"], log)
    assert not [r for r in caplog.records if "quiet" in r.getMessage()]
