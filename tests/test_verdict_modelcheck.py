"""RFC §9.1 verdict model check.

Enumerates every assignment for the 8 selected builders. With R = n selection is symmetric, so the
malicious builders are fixed to the last k nodes, k in {0, 1, 2}. Envelopes are signed once.
"""

import itertools

import pytest
from conftest import NODE_IDS, genesis_raw, seed_for
from nacl.signing import SigningKey

from matrix.genesis import parse_genesis
from matrix.model import make_envelope, request_id
from matrix.verdict import verdict

TRUE, FAKE1, FAKE2 = "a" * 64, "b" * 64, "c" * 64
RESULTS = (TRUE, "FAILED", FAKE1, FAKE2)
# What a malicious builder may send: nothing, one result, or two conflicting ones (equivocation).
MALICIOUS = [(), (TRUE,), ("FAILED",), (FAKE1,), (FAKE2,), (TRUE, FAKE1), (FAKE1, FAKE2)]
HONEST = [(), (TRUE,)]  # honest builders attest the true hash or abstain


@pytest.fixture(scope="module")
def world():
    g = parse_genesis(genesis_raw())
    keys = {i: SigningKey(seed_for(i)) for i in NODE_IDS + ["ci-release"]}
    body = {"v": 1, "repo_url": "https://github.com/org/hello", "commit": "1" * 40, "tag": "v1.2.0"}
    req = make_envelope("release", "ci-release", body, keys["ci-release"], g)
    rid = request_id(body)
    att = {
        (n, r): make_envelope("attest", n, {"request_id": rid, "result": r}, keys[n], g)
        for n in NODE_IDS
        for r in RESULTS
    }
    return g, req, att


@pytest.mark.parametrize("k", [0, 1, 2])
def test_verdict_model_check(world, k):
    g, req, att = world
    honest_ids, bad_ids = NODE_IDS[: 8 - k], NODE_IDS[8 - k :]
    scenarios = 0
    for h in itertools.product(HONEST, repeat=len(honest_ids)):
        for m in itertools.product(MALICIOUS, repeat=k):
            sent = dict(zip(honest_ids, h)) | dict(zip(bad_ids, m))
            envs = [att[n, r] for n, rs in sent.items() for r in rs]
            v = verdict(req, envs, g)  # (c) never raises
            true_votes = sum(1 for rs in sent.values() if rs == (TRUE,))
            honest_true = sum(1 for n in honest_ids if sent[n] == (TRUE,))

            if v.state == "AGREED":
                assert v.hash == TRUE  # (a) only the true hash is ever agreed
            if honest_true >= 3:
                assert (v.state, v.hash) == ("AGREED", TRUE)  # (b)
            # With <= f malicious builders no fake can reach T, so the outcome is exact.
            assert v.state == ("AGREED" if true_votes >= 3 else "PENDING"), (sent, v)
            scenarios += 1
    assert scenarios == len(HONEST) ** (8 - k) * len(MALICIOUS) ** k
