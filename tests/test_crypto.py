import json
from copy import deepcopy
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from matrix.crypto import keygen, load_key, pubkey_hex, sign, signed_bytes, verify

VEC = json.loads((Path(__file__).parent / "vectors" / "envelope.json").read_text())


def test_golden_vector():
    sk = SigningKey(bytes.fromhex(VEC["seed"]))
    assert pubkey_hex(sk) == VEC["pubkey"]
    assert signed_bytes(VEC["genesis_hash"], VEC["unsigned"]).hex() == VEC["signed_bytes_hex"]
    assert sign(sk, VEC["genesis_hash"], VEC["unsigned"]) == VEC["sig"]
    assert verify(VEC["pubkey"], VEC["genesis_hash"], VEC["unsigned"], VEC["sig"])


def test_wrong_genesis_hash_is_rejected():
    # a signature from another network must not replay here
    assert not verify(VEC["pubkey"], "cd" * 32, VEC["unsigned"], VEC["sig"])


def test_tampered_body_or_signer_is_rejected():
    for path in (("body", "result"), ("signer",), ("type",)):
        u = deepcopy(VEC["unsigned"])
        d = u
        for p in path[:-1]:
            d = d[p]
        d[path[-1]] = "tampered"
        assert not verify(VEC["pubkey"], VEC["genesis_hash"], u, VEC["sig"])


def test_wrong_key_is_rejected():
    other = pubkey_hex(SigningKey(b"\x01" * 32))
    assert not verify(other, VEC["genesis_hash"], VEC["unsigned"], VEC["sig"])


def test_roundtrip_with_fresh_key():
    seed, pub = keygen()
    sk = SigningKey(bytes.fromhex(seed))
    assert pubkey_hex(sk) == pub
    sig = sign(sk, "00" * 32, {"v": 1})
    assert verify(pub, "00" * 32, {"v": 1}, sig)


@pytest.mark.parametrize(
    "pub, gh, unsigned, sig",
    [
        ("zz", VEC["genesis_hash"], VEC["unsigned"], VEC["sig"]),
        (VEC["pubkey"], VEC["genesis_hash"], VEC["unsigned"], "00"),
        (VEC["pubkey"], VEC["genesis_hash"], VEC["unsigned"], VEC["sig"].upper()),
        (VEC["pubkey"], VEC["genesis_hash"], {"v": 1.5}, VEC["sig"]),
        (VEC["pubkey"], "é", VEC["unsigned"], VEC["sig"]),
        (None, VEC["genesis_hash"], VEC["unsigned"], VEC["sig"]),
        (VEC["pubkey"], VEC["genesis_hash"], VEC["unsigned"], None),
    ],
)
def test_verify_never_raises(pub, gh, unsigned, sig):
    assert verify(pub, gh, unsigned, sig) is False


def test_load_key(tmp_path):
    seed, pub = keygen()
    p = tmp_path / "k.key"
    p.write_text(seed + "\n")
    assert pubkey_hex(load_key(str(p))) == pub
    p.write_text(seed)
    assert pubkey_hex(load_key(str(p))) == pub


@pytest.mark.parametrize("content", ["", "abc", "A" * 64, "0" * 63, "0" * 65, "0" * 64 + "\n\n"])
def test_load_key_rejects_malformed(tmp_path, content):
    p = tmp_path / "k.key"
    p.write_text(content)
    with pytest.raises(ValueError):
        load_key(str(p))
