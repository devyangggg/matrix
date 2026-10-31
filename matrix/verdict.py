from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .genesis import Genesis


@dataclass(frozen=True)
class Verdict:
    state: str  # AGREED | BUILD_FAILED | NOT_REPRODUCIBLE | PENDING | INVALID
    hash: str | None = None  # set for AGREED
    results: dict[str, str] = field(default_factory=dict)  # signer -> result (non-equivocators)
    equivocators: frozenset[str] = frozenset()


def verdict(request_env: Any, envelopes: Iterable[Any], g: Genesis) -> Verdict:
    raise NotImplementedError
