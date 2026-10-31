import hashlib
import json
from typing import Any


def _check(o: Any) -> None:
    # json.dumps accepts floats natively, so walk the object to enforce "no floats in signed data".
    if isinstance(o, float):
        raise TypeError("floats are not allowed in canonical JSON")
    if isinstance(o, dict):
        for k, v in o.items():
            if type(k) is not str:
                raise TypeError("object keys must be str")
            _check(v)
    elif isinstance(o, (list, tuple)):
        for v in o:
            _check(v)
    elif o is not None and not isinstance(o, (str, int)):  # bool is an int subclass
        raise TypeError(f"unsupported type {type(o).__name__}")


def canonical_json(obj: Any) -> bytes:
    _check(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _no_dup_pairs(pairs: list[tuple[str, Any]]) -> dict:
    d: dict = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _reject(_: str) -> Any:
    raise ValueError("floats and NaN/Infinity are not allowed")


def loads_strict(data: bytes | str) -> Any | None:
    try:
        text = data.decode("utf-8") if isinstance(data, bytes) else data
        return json.loads(
            text, object_pairs_hook=_no_dup_pairs, parse_float=_reject, parse_constant=_reject
        )
    except Exception:  # noqa: BLE001  hostile input must never raise (invariant 1)
        return None
