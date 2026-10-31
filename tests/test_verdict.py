import pytest

from matrix.canon import canonical_json
from matrix.genesis import parse_genesis
from matrix.model import make_envelope, request_id
from matrix.select import selected
from matrix.verdict import verdict

H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64
B = [f"builder{i}" for i in range(1, 9)]


@pytest.fixture
def run(genesis, release_env, attest):
    """run({signer: result | (result, ...)}) -> Verdict for release_env."""

    def go(votes: dict, extra=()):
        envs = []
        for signer, res in votes.items():
            for r in (res,) if isinstance(res, str) else res:
                envs.append(attest(signer, r))
        return verdict(release_env, envs + list(extra), genesis)

    return go


def votes(*groups):
    """votes((H1, 3), (H2, 2)) -> builders 1-3 vote H1, builders 4-5 vote H2."""
    out, i = {}, 0
    for result, n in groups:
        for _ in range(n):
            out[B[i]] = result
            i += 1
    return out


# --- RFC §6.4: one case per verdict state --------------------------------------------------


def test_pending_without_attestations(run):
    assert run({}).state == "PENDING"


def test_pending_below_threshold(run):
    assert run(votes((H1, 2))).state == "PENDING"


def test_agreed_at_threshold(run):
    v = run(votes((H1, 3)))
    assert (v.state, v.hash) == ("AGREED", H1)


def test_agreed_despite_dissenters_and_dissent_is_visible(run):
    v = run(votes((H1, 3), (H2, 2)))
    assert (v.state, v.hash) == ("AGREED", H1)
    assert v.results["builder4"] == H2


def test_build_failed_needs_threshold_failed_votes(run):
    assert run(votes(("FAILED", 2))).state == "PENDING"
    v = run(votes(("FAILED", 3)))
    assert (v.state, v.hash) == ("BUILD_FAILED", None)


def test_not_reproducible_when_two_results_reach_threshold(run):
    assert run(votes((H1, 3), (H2, 3))).state == "NOT_REPRODUCIBLE"


def test_not_reproducible_when_no_result_can_reach_threshold(run):
    assert run(votes((H1, 2), (H2, 2), (H3, 2), ("FAILED", 2))).state == "NOT_REPRODUCIBLE"


def test_pending_while_outstanding_builders_could_still_decide(run):
    assert run(votes((H1, 2), (H2, 2), (H3, 2))).state == "PENDING"  # 2 silent: 2+2 >= 3


# --- request validity ----------------------------------------------------------------------


def test_invalid_request(genesis, genesis_dict, attest, release_env, keys):
    envs = [attest(b, H1) for b in B[:3]]
    forged = {**release_env, "sig": "0" * 128}
    bad_body = make_envelope("release", "ci-release", {"v": 1}, keys["ci-release"], genesis)
    for bad in (None, "x", {}, forged, envs[0], bad_body):
        assert verdict(bad, envs, genesis).state == "INVALID"
    other_net = parse_genesis({**genesis_dict, "network_id": "other"})
    assert verdict(release_env, envs, other_net).state == "INVALID"  # wrong genesis hash


# --- hostile attestations ------------------------------------------------------------------


def test_equivocator_is_dropped_and_reported(run):
    v = run({"builder1": (H1, H2), "builder2": H1, "builder3": H1})
    assert v.state == "PENDING"  # builder1's votes do not count
    assert v.equivocators == {"builder1"} and "builder1" not in v.results
    v = run({"builder1": (H1, H2), "builder2": H1, "builder3": H1, "builder4": H1})
    assert (v.state, v.hash) == ("AGREED", H1)


def test_equivocation_with_failed_is_also_dropped(run):
    assert run({"builder1": (H1, "FAILED"), "builder2": H1, "builder3": H1}).state == "PENDING"


def test_foreign_request_id_is_ignored(genesis, release_env, attest):
    envs = [attest(b, H1, rid="9" * 64) for b in B[:3]]
    assert verdict(release_env, envs, genesis).state == "PENDING"


def test_duplicate_envelope_counts_once(genesis, release_env, attest):
    e = attest("builder1", H1)
    assert verdict(release_env, [e] * 5, genesis).state == "PENDING"


def test_garbage_and_bad_signatures_are_ignored(genesis, release_env, attest):
    good = [attest(b, H1) for b in B[:2]]
    forged = {**attest("builder3", H1), "sig": "0" * 128}
    junk = [None, 5, "x", b"\xff", {}, [], forged, release_env]  # a release is not an attestation
    v = verdict(release_env, good + junk, genesis)
    assert v.state == "PENDING" and set(v.results) == {"builder1", "builder2"}
    assert verdict(release_env, good + [attest("builder3", H1)], genesis).state == "AGREED"


def test_accepts_raw_bytes_envelopes(genesis, release_env, attest):
    envs = [canonical_json(attest(b, H1)) for b in B[:3]]
    assert verdict(canonical_json(release_env), envs, genesis).state == "AGREED"


def test_non_selected_signer_is_ignored(genesis_dict, keys):
    genesis_dict["replicas"] = 5
    g = parse_genesis(genesis_dict)
    body = {"v": 1, "repo_url": "https://github.com/org/hello", "commit": "1" * 40, "tag": "v1.2.0"}
    req = make_envelope("release", "ci-release", body, keys["ci-release"], g)
    rid = request_id(body)
    sel = selected(rid, g.nodes, 5)
    out = [n.id for n in g.nodes if n.id not in sel]
    assert len(out) == 3

    def att(who):
        return make_envelope("attest", who, {"request_id": rid, "result": H1}, keys[who], g)

    assert verdict(req, [att(n) for n in out], g).state == "PENDING"
    assert verdict(req, [att(n) for n in sel[:3]], g).state == "AGREED"


def test_non_iterable_envelopes_do_not_raise(genesis, release_env):
    assert verdict(release_env, None, genesis).state == "INVALID"
