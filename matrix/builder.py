from dataclasses import dataclass

from .genesis import Genesis
from .model import Request


@dataclass(frozen=True)
class BuildEnv:
    data_dir: str  # <data>; work/, logs/, artifacts/ live under it
    node_id: str
    uid: int
    gid: int


@dataclass(frozen=True)
class Outcome:
    kind: str  # HASH | FAILED | ERROR | BAD_REF | BAD_RECIPE
    result: str | None  # sha256 hex for HASH, "FAILED" for FAILED, else None
    artifact_path: str | None
    reason: str  # short human-readable reason, stored in my_builds.error


async def build(
    req: Request, rid: str, g: Genesis, env: BuildEnv, attempt: int, patch: str | None = None
) -> Outcome:
    raise NotImplementedError


def classify_go_build(
    rc: int, stderr: str, rerun_rc: int | None, rerun_stderr: str | None, workdir: str
) -> str:
    raise NotImplementedError


async def cleanup_startup(env: BuildEnv) -> None:
    raise NotImplementedError


def expire_artifacts(env: BuildEnv, now: float) -> None:
    raise NotImplementedError
