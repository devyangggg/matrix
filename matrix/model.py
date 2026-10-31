from dataclasses import dataclass
from typing import Any

from .crypto import SIG_PREFIX  # noqa: F401  (defined in crypto for layering; re-exported here)
from .genesis import Genesis

PROTOCOL_V = 1
MAX_RELEASE_ENV = 4096
MAX_ATTEST_ENV = 1024
MAX_RECIPE = 4096
MAX_CERT = 65536


@dataclass(frozen=True)
class Request:
    v: int
    repo_url: str
    commit: str
    tag: str


@dataclass(frozen=True)
class Recipe:
    image: str
    package: str
    goos: str
    goarch: str
    ldflags: str
    output: str


@dataclass(frozen=True)
class Envelope:
    type: str
    signer: str
    body: dict
    sig: str
    raw: dict  # the full envelope as parsed
    msg_id: str  # sha256_hex(canonical_json(raw))


@dataclass(frozen=True)
class Certificate:
    genesis_hash: str
    request: dict
    attestations: tuple[dict, ...]


def request_id(body: dict) -> str:
    raise NotImplementedError


def valid_request(body: Any, g: Genesis) -> bool:
    raise NotImplementedError


def parse_recipe(data: bytes, g: Genesis) -> Recipe | None:
    raise NotImplementedError


def valid_ldflags(s: str) -> bool:
    raise NotImplementedError


def make_envelope(type: str, signer: str, body: dict, sk, g: Genesis) -> dict:
    raise NotImplementedError


def parse_envelope(raw: Any, g: Genesis) -> Envelope | None:
    raise NotImplementedError


def parse_certificate(raw: bytes, g: Genesis) -> Certificate | None:
    raise NotImplementedError
