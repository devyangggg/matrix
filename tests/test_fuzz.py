"""10k random mutations of valid inputs must never raise, and must never produce a forgery."""

import json
import random
from copy import deepcopy

from matrix.canon import canonical_json
from matrix.model import parse_certificate, parse_envelope
from matrix.verdict import verdict

N = 10_000
ODD = [
    None, True, False, 0, 1, -1, 2**64, 1.5, float("nan"), "", "x", "é", "\ud800", "0" * 64,
    "f" * 128, "FAILED", [], {}, [1], {"a": 1}, b"bytes",
]  # fmt: skip


def paths(o, prefix=()):
    yield prefix
    if isinstance(o, dict):
        for k, v in o.items():
            yield from paths(v, (*prefix, k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from paths(v, (*prefix, i))


def mutate_obj(rng, obj):
    obj = deepcopy(obj)
    path = rng.choice([p for p in paths(obj)])
    if not path:
        return rng.choice(ODD)
    parent = obj
    for p in path[:-1]:
        parent = parent[p]
    op = rng.choice(["replace", "delete", "add", "hexflip"])
    if op == "replace":
        parent[path[-1]] = rng.choice(ODD)
    elif op == "delete":
        del parent[path[-1]]
    elif op == "add" and isinstance(parent, dict):
        parent[rng.choice(["x", "v", "sig", "body", ""])] = rng.choice(ODD)
    elif op == "hexflip" and isinstance(parent[path[-1]], str) and parent[path[-1]]:
        s = parent[path[-1]]
        i = rng.randrange(len(s))
        parent[path[-1]] = s[:i] + rng.choice("0123456789abcdefg") + s[i + 1 :]
    return obj


def mutate_text(rng, text: str) -> str | bytes:
    i = rng.randrange(len(text) + 1)
    op = rng.choice(["del", "ins", "trunc", "dupkey", "bytes", "pad"])
    if op == "del":
        return text[:i] + text[i + 1 :]
    if op == "ins":
        return text[:i] + rng.choice('{}[]",:\\ 0x\ud800') + text[i:]
    if op == "trunc":
        return text[:i]
    if op == "dupkey":
        return text.replace("{", '{"v":1,"type":"attest","signer":"x",', 1)
    if op == "pad":
        return text + " " * rng.randrange(5000)
    raw = bytearray(text.encode())
    if raw:
        raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
    return bytes(raw)


def mutate(rng, obj):
    if rng.random() < 0.5:
        return mutate_obj(rng, obj)
    return mutate_text(rng, json.dumps(obj, sort_keys=True))


def test_fuzz_envelopes_certificates_and_verdict(genesis, release_env, attest):
    rng = random.Random(20261031)
    atts = [attest(f"builder{i}", "f" * 64) for i in range(1, 5)]
    cert = {
        "v": 1,
        "genesis_hash": genesis.hash,
        "request": release_env,
        "attestations": atts,
    }
    seeds = [release_env, *atts]
    originals = {canonical_json(s) for s in seeds}

    for i in range(N):
        src = rng.choice(seeds)
        m = mutate(rng, src)
        try:
            e = parse_envelope(m, genesis)
            if e is not None:
                # Unforgeability: only a no-op mutation (formatting, key order) may be accepted.
                assert canonical_json(e.raw) in originals
            parse_certificate(
                m if isinstance(m, bytes) else json.dumps(m, default=str).encode(), genesis
            )

            c = mutate(rng, cert)
            if isinstance(c, dict):
                v = verdict(c.get("request"), c.get("attestations", []), genesis)
                assert v.state in {
                    "AGREED",
                    "PENDING",
                    "INVALID",
                    "NOT_REPRODUCIBLE",
                    "BUILD_FAILED",
                }
            verdict(m, [m, *atts], genesis)
            verdict(release_env, [mutate(rng, a) for a in atts], genesis)
        except Exception as exc:
            raise AssertionError(f"iteration {i}: {m!r}") from exc
