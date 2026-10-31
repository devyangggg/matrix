from dataclasses import dataclass


class GenesisError(Exception):
    pass


@dataclass(frozen=True)
class Node:
    id: str
    operator: str
    addr: str  # "host:port"
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
        raise NotImplementedError

    def signer(self, id: str) -> Signer | None:
        raise NotImplementedError


def load_genesis(path: str) -> Genesis:
    raise NotImplementedError


def parse_genesis(raw: dict) -> Genesis:
    raise NotImplementedError


def file_genesis_hash(path: str) -> str:
    raise NotImplementedError
