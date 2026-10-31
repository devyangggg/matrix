import re
from collections import Counter
from dataclasses import dataclass

from .canon import canonical_json, loads_strict, sha256_hex


class GenesisError(Exception):
    pass


@dataclass(frozen=True)
class Node:
    id: str
    operator: str
    addr: str | None  # "host:port"; optional: ceremony genesis has none (found by hellos)
    pubkey: str


@dataclass(frozen=True)
class Signer:
    id: str
    pubkey: str


@dataclass(frozen=True)
class Genesis:
    network_id: str
    f: int
    replicas: int
    threshold: int
    build_timeout_s: int
    request_ttl_s: int
    sync_interval_s: int
    allowed_repos: tuple[str, ...]
    allowed_images: dict[str, str]
    allowed_goos: tuple[str, ...]
    allowed_goarch: tuple[str, ...]
    release_signers: tuple[Signer, ...]
    nodes: tuple[Node, ...]
    hash: str  # sha256_hex(canonical_json(raw genesis))

    def node(self, id: str) -> Node | None:
        return next((n for n in self.nodes if n.id == id), None)

    def signer(self, id: str) -> Signer | None:
        return next((s for s in self.release_signers if s.id == id), None)


_KEYS = {
    "network_id", "f", "replicas", "threshold", "build_timeout_s", "request_ttl_s",
    "sync_interval_s", "allowed_repos", "allowed_images", "allowed_goos", "allowed_goarch",
    "release_signers", "nodes",
}  # fmt: skip
_INTS = ("f", "replicas", "threshold", "build_timeout_s", "request_ttl_s", "sync_interval_s")
_ID = re.compile(r"[A-Za-z0-9_-]{1,32}", re.ASCII)
_PUBKEY = re.compile(r"[0-9a-f]{64}", re.ASCII)
_ADDR = re.compile(r"[A-Za-z0-9.-]+:([0-9]{1,5})", re.ASCII)
_REPO = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
_IMAGE = re.compile(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)  # image keys, goos/goarch, operators


def _need(ok: bool, msg: str) -> None:
    if not ok:
        raise GenesisError(msg)


def _match(rx: re.Pattern, v: object) -> bool:
    return isinstance(v, str) and rx.fullmatch(v) is not None


def _str_list(raw: dict, key: str, rx: re.Pattern) -> tuple[str, ...]:
    v = raw[key]
    _need(isinstance(v, list) and len(v) > 0, f"{key} must be a non-empty list")
    _need(all(_match(rx, x) for x in v), f"{key} has an invalid entry")
    return tuple(v)


def _dict_list(raw: dict, key: str, *allowed: set[str]) -> list[dict]:
    v = raw[key]
    _need(isinstance(v, list) and len(v) > 0, f"{key} must be a non-empty list")
    _need(
        all(isinstance(x, dict) and set(x) in allowed for x in v),
        f"{key} entries need exactly one of {[sorted(a) for a in allowed]}",
    )
    return v


def parse_genesis(raw: dict) -> Genesis:
    _need(isinstance(raw, dict), "genesis must be a JSON object")
    _need(set(raw) == _KEYS, f"genesis keys must be exactly {sorted(_KEYS)}")
    for k in _INTS:
        _need(type(raw[k]) is int and raw[k] > 0, f"{k} must be a positive integer")
    _need(_match(_NAME, raw["network_id"]), "network_id is invalid")

    repos = _str_list(raw, "allowed_repos", _REPO)
    goos = _str_list(raw, "allowed_goos", _NAME)
    goarch = _str_list(raw, "allowed_goarch", _NAME)
    images = raw["allowed_images"]
    _need(isinstance(images, dict) and len(images) > 0, "allowed_images must be non-empty")
    _need(
        all(_match(_NAME, k) and _match(_IMAGE, v) for k, v in images.items()),
        "allowed_images must map names to name@sha256:<64 hex>",
    )

    signers = tuple(Signer(**s) for s in _dict_list(raw, "release_signers", {"id", "pubkey"}))
    # addr is optional (RFC rev 5 §7.2): addresses are not security relevant, and an IP inside
    # genesis would change the network's hash whenever DHCP does.
    node_keys = ({"id", "operator", "pubkey"}, {"id", "operator", "addr", "pubkey"})
    nodes = tuple(
        Node(n["id"], n["operator"], n.get("addr"), n["pubkey"])
        for n in _dict_list(raw, "nodes", *node_keys)
    )
    ids = [x.id for x in signers + nodes]
    keys = [x.pubkey for x in signers + nodes]
    _need(all(_match(_ID, i) for i in ids), "ids must match [A-Za-z0-9_-]{1,32}")
    _need(len(set(ids)) == len(ids), "node and signer ids must be unique across both lists")
    _need(all(_match(_PUBKEY, k) for k in keys), "public keys must be 64 lowercase hex")
    _need(len(set(keys)) == len(keys), "public keys must be distinct")
    for n in nodes:
        _need(_match(_NAME, n.operator), f"{n.id}: operator is invalid")
    for raw_node, n in zip(raw["nodes"], nodes):
        if "addr" in raw_node:  # present means valid; an explicit null is rejected too
            m = _ADDR.fullmatch(n.addr) if isinstance(n.addr, str) else None
            _need(m is not None and int(m[1]) <= 65535, f"{n.id}: addr must be host:port")

    f, n_nodes = raw["f"], len(nodes)
    _need(n_nodes >= 4 * f, "need n >= 4f")
    _need(2 * f + 1 <= raw["replicas"] <= n_nodes, "need 2f+1 <= replicas <= n")
    _need(raw["threshold"] == f + 1, "threshold must equal f+1")
    _need(raw["build_timeout_s"] < raw["request_ttl_s"], "build_timeout_s must be < request_ttl_s")
    per_op = Counter(n.operator for n in nodes)
    _need(max(per_op.values()) <= f, "no operator may run more than f nodes")

    return Genesis(
        network_id=raw["network_id"],
        f=f,
        replicas=raw["replicas"],
        threshold=raw["threshold"],
        build_timeout_s=raw["build_timeout_s"],
        request_ttl_s=raw["request_ttl_s"],
        sync_interval_s=raw["sync_interval_s"],
        allowed_repos=repos,
        allowed_images=dict(images),
        allowed_goos=goos,
        allowed_goarch=goarch,
        release_signers=signers,
        nodes=nodes,
        hash=sha256_hex(canonical_json(raw)),
    )


def load_genesis(path: str) -> Genesis:
    try:
        with open(path, "rb") as f:
            raw = loads_strict(f.read())
    except OSError as e:
        raise GenesisError(f"cannot read genesis: {e}") from e
    _need(isinstance(raw, dict), "genesis is not a valid JSON object (duplicate keys, floats?)")
    return parse_genesis(raw)


def file_genesis_hash(path: str) -> str:
    return load_genesis(path).hash
