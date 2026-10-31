"""Contract tests for the standalone dev genesis generator."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "dev_genesis.py"
IMAGE = "golang@sha256:" + "a" * 64
REPOS = ("https://github.com/org/hello", "https://github.com/other/project")
TOP_LEVEL = {
    "network_id",
    "f",
    "replicas",
    "threshold",
    "build_timeout_s",
    "request_ttl_s",
    "sync_interval_s",
    "allowed_repos",
    "allowed_images",
    "allowed_goos",
    "allowed_goarch",
    "release_signers",
    "nodes",
}


def run_generator(
    out: Path, addrs: str, profile: str, *extra: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--out",
            str(out),
            "--addrs",
            addrs,
            "--profile",
            profile,
            "--repo",
            REPOS[0],
            "--repo",
            REPOS[1],
            "--image",
            IMAGE,
            *extra,
        ],
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.mark.parametrize("addrs", ["compose", "local"])
@pytest.mark.parametrize(
    "profile,build_timeout,sync_interval", [("demo", 45, 5), ("full", 150, 10)]
)
def test_genesis_and_private_keys(tmp_path, addrs, profile, build_timeout, sync_interval):
    out = tmp_path / "nested" / "dev"
    run_generator(out, addrs, profile)

    raw = json.loads((out / "genesis.json").read_bytes())
    canonical = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    assert (out / "genesis.sha256").read_text(encoding="ascii") == hashlib.sha256(
        canonical
    ).hexdigest() + "\n"
    assert set(raw) == TOP_LEVEL
    assert (raw["network_id"], raw["f"], raw["replicas"], raw["threshold"]) == (
        "matrix-dev",
        2,
        8,
        3,
    )
    assert (raw["build_timeout_s"], raw["sync_interval_s"], raw["request_ttl_s"]) == (
        build_timeout,
        sync_interval,
        3600,
    )
    assert raw["allowed_repos"] == list(REPOS)
    assert raw["allowed_images"] == {"go1.23": IMAGE}
    assert raw["allowed_goos"] == ["linux", "darwin", "windows"]
    assert raw["allowed_goarch"] == ["amd64", "arm64"]
    assert (out / "keys").stat().st_mode & 0o777 == 0o700
    assert len(raw["nodes"]) == 8
    assert [node["id"] for node in raw["nodes"]] == [f"builder{i}" for i in range(1, 9)]
    assert [node["operator"] for node in raw["nodes"]] == [
        f"laptop{letter}" for letter in "ABCD" for _ in range(2)
    ]
    assert [node["addr"] for node in raw["nodes"]] == [
        f"builder{i}:7700" if addrs == "compose" else f"127.0.0.1:{7699 + i}" for i in range(1, 9)
    ]
    assert [signer["id"] for signer in raw["release_signers"]] == ["ci-release"]
    key_pubkeys = [(f"builder{i}", node["pubkey"]) for i, node in enumerate(raw["nodes"], 1)]
    key_pubkeys.append(("release", raw["release_signers"][0]["pubkey"]))
    assert len({pubkey for _, pubkey in key_pubkeys}) == 9
    for name, pubkey in key_pubkeys:
        key_path = out / "keys" / f"{name}.key"
        assert key_path.stat().st_mode & 0o777 == 0o600
        seed_hex = key_path.read_text(encoding="ascii").strip()
        assert len(seed_hex) == 64
        assert SigningKey(bytes.fromhex(seed_hex)).verify_key.encode().hex() == pubkey


def test_rerun_does_not_overwrite_private_keys(tmp_path):
    out = tmp_path / "dev"
    run_generator(out, "local", "demo")
    before = (out / "keys" / "builder1.key").read_bytes()
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--out",
            str(out),
            "--addrs",
            "local",
            "--profile",
            "demo",
            "--repo",
            REPOS[0],
            "--image",
            IMAGE,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert (out / "keys" / "builder1.key").read_bytes() == before


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--repo", "http://github.com/org/hello"),
        ("--repo", "https://github.com/org/hello.git/extra"),
        ("--image", "golang:latest"),
        ("--image", "golang@sha256:" + "A" * 64),
    ],
)
def test_invalid_genesis_inputs_are_rejected_before_keys(tmp_path, flag, value):
    out = tmp_path / "dev"
    args = [
        sys.executable,
        str(SCRIPT),
        "--out",
        str(out),
        "--addrs",
        "local",
        "--profile",
        "demo",
        "--repo",
        REPOS[0],
        "--image",
        IMAGE,
    ]
    args[args.index(flag) + 1] = value
    result = subprocess.run(args, check=False, capture_output=True, text=True)
    assert result.returncode != 0
    assert not (out / "keys").exists()


@pytest.mark.parametrize("addrs", ["compose", "local"])
def test_four_node_profile_one_builder_per_laptop(tmp_path, addrs):
    from matrix.genesis import load_genesis

    out = tmp_path / "dev4"
    run_generator(out, addrs, "demo", "--nodes", "4")
    raw = json.loads((out / "genesis.json").read_bytes())
    assert (raw["f"], raw["replicas"], raw["threshold"]) == (1, 4, 2)
    assert [n["id"] for n in raw["nodes"]] == [f"builder{i}" for i in range(1, 5)]
    assert [n["operator"] for n in raw["nodes"]] == [f"laptop{x}" for x in "ABCD"]
    assert [n["addr"] for n in raw["nodes"]] == [
        f"builder{i}:7700" if addrs == "compose" else f"127.0.0.1:{7699 + i}" for i in range(1, 5)
    ]
    assert sorted(p.name for p in (out / "keys").iterdir()) == [
        "builder1.key", "builder2.key", "builder3.key", "builder4.key", "release.key",
    ]  # fmt: skip
    g = load_genesis(str(out / "genesis.json"))  # passes every genesis rule
    assert (out / "genesis.sha256").read_text().strip() == g.hash
