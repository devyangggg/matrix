from typing import Any


def canonical_json(obj: Any) -> bytes:
    raise NotImplementedError


def sha256_hex(data: bytes) -> str:
    raise NotImplementedError


def loads_strict(data: bytes | str) -> Any | None:
    raise NotImplementedError
