from typing import Any

from aiohttp import web

from .builder import BuildEnv
from .genesis import Genesis, Node
from .protocol import Engine
from .store import Store


def make_app(engine: Engine, store: Store, g: Genesis, me: Node, env: BuildEnv) -> web.Application:
    raise NotImplementedError


class PeerClient:
    def __init__(self, g: Genesis, me: Node):
        raise NotImplementedError

    async def broadcast_request(self, env: dict) -> None:
        raise NotImplementedError

    async def broadcast_attest(self, env: dict, only: list[str] | None = None) -> None:
        raise NotImplementedError

    async def get_json(self, node_id: str, path: str) -> Any | None:
        raise NotImplementedError

    async def get_bytes(self, node_id: str, path: str, limit: int) -> bytes | None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError
