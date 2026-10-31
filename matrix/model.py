import re
import tomllib
from dataclasses import dataclass
from typing import Any

from .canon import canonical_json, loads_strict, sha256_hex
from .crypto import SIG_PREFIX, sign, verify  # noqa: F401  SIG_PREFIX re-exported (LLD L14)
from .genesis import Genesis

PROTOCOL_V = 1
MAX_RELEASE_ENV = 4096
MAX_ATTEST_ENV = 1024
MAX_RECIPE = 4096
MAX_CERT = 65536

_COMMIT = re.compile(r"[0-9a-f]{40}", re.ASCII)
_TAG = re.compile(r"[A-Za-z0-9_.+-]{1,64}", re.ASCII)
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SIG = re.compile(r"[0-9a-f]{128}", re.ASCII)
_RESULT = re.compile(r"[0-9a-f]{64}|FAILED", re.ASCII)
_PACKAGE = re.compile(r"\./[A-Za-z0-9_./-]*", re.ASCII)
_OUTPUT = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_LDX = re.compile(r"[A-Za-z0-9_./-]+\.[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_./:@+-]{0,128}", re.ASCII)


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


def _m(rx: re.Pattern, v: object) -> bool:
    return isinstance(v, str) and rx.fullmatch(v) is not None


def _is_one(v: object) -> bool:
    return type(v) is int and v == PROTOCOL_V  # `True == 1`, so check the type too


def request_id(body: dict) -> str:
    return sha256_hex(canonical_json(body))


def valid_request(body: Any, g: Genesis) -> bool:
    return (
        isinstance(body, dict)
        and set(body) == {"v", "repo_url", "commit", "tag"}
        and _is_one(body["v"])
        and isinstance(body["repo_url"], str)
        and body["repo_url"] in g.allowed_repos
        and _m(_COMMIT, body["commit"])
        and _m(_TAG, body["tag"])
    )


def valid_ldflags(s: str) -> bool:
    if not isinstance(s, str):
        return False
    if s == "":
        return True
    if len(s) > 512:
        return False
    tokens = s.split(" ")
    i = 0
    while i < len(tokens):
        if tokens[i] in ("-s", "-w", "-buildid="):
            i += 1
        elif tokens[i] == "-X" and i + 1 < len(tokens) and _LDX.fullmatch(tokens[i + 1]):
            i += 2
        else:
            return False
    return True


_RECIPE_KEYS = {"image", "package", "goos", "goarch", "ldflags", "output"}


def parse_recipe(data: bytes, g: Genesis) -> Recipe | None:
    try:
        if len(data) > MAX_RECIPE:
            return None
        doc = tomllib.loads(data.decode("utf-8"))
        if set(doc) != {"build"} or not isinstance(doc["build"], dict):
            return None
        b = doc["build"]
        if set(b) != _RECIPE_KEYS or not all(isinstance(v, str) for v in b.values()):
            return None
        if (
            b["image"] not in g.allowed_images
            or b["goos"] not in g.allowed_goos
            or b["goarch"] not in g.allowed_goarch
            or not _m(_PACKAGE, b["package"])
            or ".." in b["package"].split("/")
            or not valid_ldflags(b["ldflags"])
            or not _m(_OUTPUT, b["output"])
            or b["output"] in (".", "..")
        ):
            return None
        return Recipe(**b)
    except Exception:  # noqa: BLE001  hostile input must never raise (invariant 1)
        return None


def make_envelope(type: str, signer: str, body: dict, sk, g: Genesis) -> dict:
    unsigned = {"v": PROTOCOL_V, "type": type, "signer": signer, "body": body}
    return {**unsigned, "sig": sign(sk, g.hash, unsigned)}


def _valid_body(type: str, body: Any, g: Genesis) -> bool:
    if type == "release":
        return valid_request(body, g)
    return (
        isinstance(body, dict)
        and set(body) == {"request_id", "result"}
        and _m(_HEX64, body["request_id"])
        and _m(_RESULT, body["result"])
    )


def parse_envelope(raw: Any, g: Genesis) -> Envelope | None:
    try:
        if isinstance(raw, (bytes, str)):
            if len(raw) > MAX_RELEASE_ENV:
                return None
            raw = loads_strict(raw)
        if not isinstance(raw, dict) or set(raw) != {"v", "type", "signer", "body", "sig"}:
            return None
        typ, signer, body = raw["type"], raw["signer"], raw["body"]
        if not _is_one(raw["v"]) or typ not in ("release", "attest"):
            return None
        if not isinstance(signer, str) or not _m(_SIG, raw["sig"]):
            return None
        canon = canonical_json(raw)
        if len(canon) > (MAX_RELEASE_ENV if typ == "release" else MAX_ATTEST_ENV):
            return None
        if not _valid_body(typ, body, g):
            return None
        who = g.signer(signer) if typ == "release" else g.node(signer)
        if who is None:
            return None
        unsigned = {"v": raw["v"], "type": typ, "signer": signer, "body": body}
        if not verify(who.pubkey, g.hash, unsigned, raw["sig"]):
            return None
        return Envelope(typ, signer, body, raw["sig"], raw, sha256_hex(canon))
    except Exception:  # noqa: BLE001  hostile input must never raise (invariant 1)
        return None


def parse_certificate(raw: bytes, g: Genesis) -> Certificate | None:
    try:
        if len(raw) > MAX_CERT:
            return None
        c = loads_strict(raw)
        if not isinstance(c, dict) or set(c) != {"v", "genesis_hash", "request", "attestations"}:
            return None
        atts = c["attestations"]
        if (
            not _is_one(c["v"])
            or not _m(_HEX64, c["genesis_hash"])
            or not isinstance(c["request"], dict)
            or not isinstance(atts, list)
            or not 1 <= len(atts) <= 2 * len(g.nodes)
            or not all(isinstance(a, dict) for a in atts)
        ):
            return None
        return Certificate(c["genesis_hash"], c["request"], tuple(atts))
    except Exception:  # noqa: BLE001  hostile input must never raise (invariant 1)
        return None
