"""Shared deterministic test kit (AGENTS §5.3). Test keys are for tests only."""

import hashlib

import pytest
from nacl.signing import SigningKey

NODE_IDS = [f"builder{i}" for i in range(1, 9)]
SIGNER_IDS = ["maintainer-alice", "ci-release"]
OPERATORS = ["laptopA", "laptopB", "laptopC", "laptopD"]
REPO = "https://github.com/org/hello"
COMMIT = "1" * 40
IMAGE = "golang@sha256:" + "a" * 64


def seed_for(id: str) -> bytes:
    return hashlib.sha256(b"matrix-test:" + id.encode()).digest()


def _pub(id: str) -> str:
    return SigningKey(seed_for(id)).verify_key.encode().hex()


def genesis_raw() -> dict:
    return {
        "network_id": "matrix-test",
        "f": 2,
        "replicas": 8,
        "threshold": 3,
        "build_timeout_s": 45,
        "request_ttl_s": 3600,
        "sync_interval_s": 5,
        "allowed_repos": [REPO],
        "allowed_images": {"go1.23": IMAGE},
        "allowed_goos": ["linux", "darwin", "windows"],
        "allowed_goarch": ["amd64", "arm64"],
        "release_signers": [{"id": s, "pubkey": _pub(s)} for s in SIGNER_IDS],
        "nodes": [
            {
                "id": n,
                "operator": OPERATORS[i // 2],
                "addr": f"127.0.0.1:{7700 + i}",
                "pubkey": _pub(n),
            }
            for i, n in enumerate(NODE_IDS)
        ],
    }


@pytest.fixture
def genesis_dict() -> dict:
    """A fresh, mutable raw genesis (for tests that need to break it)."""
    return genesis_raw()


@pytest.fixture
def genesis():
    from matrix.genesis import parse_genesis

    return parse_genesis(genesis_raw())


@pytest.fixture
def keys() -> dict[str, SigningKey]:
    return {id: SigningKey(seed_for(id)) for id in NODE_IDS + SIGNER_IDS}


@pytest.fixture
def release_env(genesis, keys) -> dict:
    """Signed release envelope for v1.2.0 at commit "1"*40, signed by ci-release."""
    from matrix.model import make_envelope

    body = {"v": 1, "repo_url": REPO, "commit": COMMIT, "tag": "v1.2.0"}
    return make_envelope("release", "ci-release", body, keys["ci-release"], genesis)


@pytest.fixture
def attest(genesis, keys, release_env):
    """attest(signer, result, request_id=None) -> signed attest envelope for release_env."""
    from matrix.model import make_envelope, request_id

    default_rid = request_id(release_env["body"])

    def make(signer: str, result: str, rid: str | None = None) -> dict:
        body = {"request_id": rid or default_rid, "result": result}
        return make_envelope("attest", signer, body, keys[signer], genesis)

    return make


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, dt: float) -> None:
        self.now += dt


@pytest.fixture
def clock() -> Clock:
    return Clock()
