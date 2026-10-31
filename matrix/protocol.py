import time
from typing import TYPE_CHECKING

from .builder import BuildEnv
from .faults import Fault
from .genesis import Genesis, Node
from .store import Store

if TYPE_CHECKING:
    from .net import PeerClient


class Engine:
    def __init__(
        self,
        g: Genesis,
        me: Node,
        sk,
        store: Store,
        peers: "PeerClient",
        env: BuildEnv,
        fault: Fault,
        clock=time.time,
    ):
        raise NotImplementedError

    async def on_request(self, raw: bytes | dict) -> tuple[int, dict]:
        raise NotImplementedError

    async def on_attest(self, raw: bytes | dict, from_hint: str | None) -> tuple[int, dict]:
        raise NotImplementedError

    async def build_worker(self) -> None:
        raise NotImplementedError

    async def sync_loop(self) -> None:
        raise NotImplementedError

    async def recover(self) -> None:
        raise NotImplementedError

    def detect_evidence(self, rid: str) -> None:
        raise NotImplementedError

    def is_settled(self, rid: str) -> bool:
        raise NotImplementedError
