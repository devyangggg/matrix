import json
from pathlib import Path

import pytest

from matrix.canon import canonical_json, loads_strict, sha256_hex

VECTORS = Path(__file__).parent / "vectors"


def _vec(name):
    return json.loads((VECTORS / name).read_text())


@pytest.mark.parametrize("v", _vec("canonical.json"))
def test_canonical_vectors(v):
    assert canonical_json(v["input"]).decode("utf-8") == v["canonical"]


def test_request_id_vector():
    v = _vec("request.json")
    raw = canonical_json(v["body"])
    assert raw.decode() == v["canonical"]
    assert sha256_hex(raw) == v["request_id"]


def test_sha256_hex_known_value():
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.mark.parametrize(
    "obj",
    [1.5, {"a": 1.0}, [[0.1]], {"a": {"b": [float("nan")]}}, {1: "x"}, {"a": b"x"}, {"a": {1, 2}}],
)
def test_canonical_json_rejects_non_canonical_types(obj):
    with pytest.raises(TypeError):
        canonical_json(obj)


def test_bool_is_kept_as_json_bool():
    assert canonical_json({"a": True, "b": 1}) == b'{"a":true,"b":1}'


@pytest.mark.parametrize(
    "text",
    ['{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '[{"x":1,"x":1}]'],
)
def test_loads_strict_rejects_duplicate_keys(text):
    assert loads_strict(text) is None


@pytest.mark.parametrize(
    "text", ["1.5", '{"a":1e5}', '{"a":1.0}', "NaN", "[Infinity]", "-Infinity"]
)
def test_loads_strict_rejects_floats_and_constants(text):
    assert loads_strict(text) is None


def test_loads_strict_accepts_valid_and_bytes():
    assert loads_strict('{"a":[1,true,null,"x"]}') == {"a": [1, True, None, "x"]}
    assert loads_strict('{"a":"é"}'.encode()) == {"a": "é"}


@pytest.mark.parametrize(
    "data", [b"\xff\xfe", b"", "", "{", '{"a":', "[" * 100000, "1" * 5000, b"\xef\xbb\xbf{}"]
)
def test_loads_strict_never_raises(data):
    assert loads_strict(data) is None
