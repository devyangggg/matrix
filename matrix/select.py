from collections.abc import Sequence

from .canon import sha256_hex
from .genesis import Node


def selected(request_id: str, nodes: Sequence[Node], r: int) -> list[str]:
    scored = sorted(nodes, key=lambda n: sha256_hex(f"{request_id}:{n.pubkey}".encode()))
    return [n.id for n in scored[:r]]
