from collections.abc import Sequence

from .genesis import Node


def selected(request_id: str, nodes: Sequence[Node], r: int) -> list[str]:
    raise NotImplementedError
