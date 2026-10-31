"""Store (LLD §3.7) on `:memory:` and on a real file."""

import json
import sqlite3

import pytest

from matrix.canon import canonical_json
from matrix.model import Envelope, parse_envelope, request_id
from matrix.store import Store

H1, H2 = "a" * 64, "b" * 64


@pytest.fixture(params=["memory", "file"])
def path(request, tmp_path):
    return ":memory:" if request.param == "memory" else str(tmp_path / "matrix.db")


@pytest.fixture
def store(path):
    return Store(path)


@pytest.fixture
def rid(release_env):
    return request_id(release_env["body"])


@pytest.fixture
def req(store, rid, release_env):
    assert store.add_request(rid, release_env, 100.0, "RECEIVED")
    return rid


# --- requests --------------------------------------------------------------------------------


def test_request_roundtrip_is_canonical_json_and_idempotent(store, rid, release_env):
    assert store.add_request(rid, release_env, 100.0, "RECEIVED") is True
    assert store.add_request(rid, release_env, 999.0, "SHED") is False  # known: untouched
    row = store.get_request(rid)
    assert (row["id"], row["received_at"], row["phase"]) == (rid, 100.0, "RECEIVED")
    assert row["envelope"] == canonical_json(release_env).decode()
    assert store.get_request("9" * 64) is None


def test_request_windows(store, release_env, keys, genesis):
    from matrix.model import make_envelope

    def add(tag, t):
        body = {**release_env["body"], "tag": tag}
        env = make_envelope("release", "ci-release", body, keys["ci-release"], genesis)
        store.add_request(request_id(body), env, t, "OBSERVING")
        return request_id(body)

    old, edge, fresh = add("v1", 100.0), add("v2", 500.0), add("v3", 900.0)
    # list_requests: received_at >= since (inclusive), oldest first
    assert [r["id"] for r in store.list_requests(0)] == [old, edge, fresh]
    assert [r["id"] for r in store.list_requests(500.0)] == [edge, fresh]
    assert store.list_requests(901.0) == []
    # live_requests: received_at > now - ttl (exclusive), so a request exactly ttl old is dead
    assert [r["id"] for r in store.live_requests(1000.0, 500)] == [fresh]
    assert [r["id"] for r in store.live_requests(1000.0, 501)] == [edge, fresh]


def test_set_phase(store, req):
    store.set_phase(req, "SHED")
    assert store.get_request(req)["phase"] == "SHED"


# --- attestations ----------------------------------------------------------------------------


def parsed(genesis, attest, signer, result) -> Envelope:
    e = parse_envelope(attest(signer, result), genesis)
    assert e is not None
    return e


def test_attestation_is_stored_once_per_msg_id(store, req, genesis, attest):
    e = parsed(genesis, attest, "builder2", H1)
    assert store.add_attestation(e, 101.0) is True
    assert store.add_attestation(e, 102.0) is False
    assert store.attestation_count(req, "builder2") == 1
    assert store.attestations(req) == [e.raw]  # the exact envelope comes back as a dict


def test_count_is_per_signer_and_distinct_results_count_separately(store, req, genesis, attest):
    for signer, result in (("builder2", H1), ("builder2", H2), ("builder3", H1)):
        store.add_attestation(parsed(genesis, attest, signer, result), 101.0)
    assert store.attestation_count(req, "builder2") == 2
    assert store.attestation_count(req, "builder3") == 1
    assert store.attestation_count(req, "builder4") == 0
    assert store.attestation_count("9" * 64, "builder2") == 0


def test_attestations_are_ordered_by_arrival(store, req, genesis, attest):
    a, b, c = (parsed(genesis, attest, s, H1) for s in ("builder4", "builder2", "builder3"))
    for e, t in ((a, 3.0), (b, 1.0), (c, 2.0)):
        store.add_attestation(e, t)
    assert [e["signer"] for e in store.attestations(req)] == ["builder2", "builder3", "builder4"]


def test_attestation_for_an_unknown_request_is_rejected_by_the_database(store, genesis, attest):
    e = parsed(genesis, attest, "builder2", H1)  # its request was never stored
    with pytest.raises(sqlite3.IntegrityError):
        store.add_attestation(e, 1.0)


# --- own builds ------------------------------------------------------------------------------


def test_upsert_build_updates_only_the_given_columns(store, req):
    assert store.get_build(req) is None
    store.upsert_build(req, started_at=5.0)
    store.upsert_build(req, error="docker down")
    row = store.get_build(req)
    assert (row["started_at"], row["error"], row["result"]) == (5.0, "docker down", None)
    store.upsert_build(req, error="timeout", finished_at=9.0)
    row = store.get_build(req)
    assert (row["started_at"], row["error"], row["finished_at"]) == (5.0, "timeout", 9.0)
    assert set(row.keys()) == {
        "request_id", "result", "artifact_path", "error", "log_path", "started_at", "finished_at",
    }  # fmt: skip


@pytest.mark.parametrize("field", ["request_id", "x; DROP TABLE requests", "result=1, error"])
def test_upsert_build_rejects_unknown_columns(store, req, field):
    with pytest.raises(ValueError):
        store.upsert_build(req, **{field: "x"})
    assert store.get_request(req) is not None


def test_record_own_attestation_commits_all_three_effects(store, req, genesis, attest):
    store.upsert_build(req, started_at=1.0)
    e = parsed(genesis, attest, "builder1", H1)
    store.record_own_attestation(req, H1, "/data/artifacts/" + H1, e, 50.0)
    build = store.get_build(req)
    assert (build["result"], build["artifact_path"], build["finished_at"]) == (
        H1,
        "/data/artifacts/" + H1,
        50.0,
    )
    assert build["started_at"] == 1.0  # earlier columns survive
    assert store.get_request(req)["phase"] == "ATTESTED"
    assert store.attestations(req) == [e.raw]


def test_record_own_attestation_is_all_or_nothing(store, req, genesis, attest, release_env):
    store.upsert_build(req, started_at=1.0)
    # the attestation row fails its foreign key (it names another request): nothing may stick
    e = parse_envelope(attest("builder1", H1, rid="7" * 64), genesis)
    assert e is not None
    with pytest.raises(sqlite3.IntegrityError):
        store.record_own_attestation(req, H1, "/p", e, 50.0)
    build = store.get_build(req)
    assert (build["result"], build["artifact_path"], build["finished_at"]) == (None, None, None)
    assert store.get_request(req)["phase"] == "RECEIVED"
    assert store.attestations(req) == []
    # the connection is usable afterwards (the failed transaction was rolled back, not left open)
    store.set_phase(req, "BUILDING")
    assert store.get_request(req)["phase"] == "BUILDING"


def test_record_own_attestation_without_a_prior_build_row(store, req, genesis, attest):
    store.record_own_attestation(
        req, "FAILED", None, parsed(genesis, attest, "builder1", "FAILED"), 7.0
    )
    build = store.get_build(req)
    assert (build["result"], build["artifact_path"]) == ("FAILED", None)


def test_artifact_path_looks_up_by_result(store, req, genesis, attest):
    assert store.artifact_path(H1) is None
    store.record_own_attestation(
        req, H1, "/art/" + H1, parsed(genesis, attest, "builder1", H1), 1.0
    )
    assert store.artifact_path(H1) == "/art/" + H1
    assert store.artifact_path(H2) is None
    assert store.artifact_path("../../etc/passwd") is None  # never a filesystem lookup


def test_a_failed_build_has_no_artifact_path(store, req, genesis, attest):
    store.record_own_attestation(
        req, "FAILED", None, parsed(genesis, attest, "builder1", "FAILED"), 1.0
    )
    assert store.artifact_path("FAILED") is None


# --- evidence --------------------------------------------------------------------------------


def test_evidence_is_unique_per_kind_signer_request(store, req, genesis, attest):
    proof = [attest("builder3", H1), attest("builder3", H2)]
    assert store.add_evidence("EQUIVOCATION", "builder3", req, proof, 10.0) is True
    assert store.add_evidence("EQUIVOCATION", "builder3", req, proof, 11.0) is False
    assert store.add_evidence("DISAGREE", "builder3", req, proof[:1], 12.0) is True  # other kind
    assert store.add_evidence("EQUIVOCATION", "builder4", req, proof, 13.0) is True  # other signer
    rows = store.list_evidence(0)
    assert [r["id"] for r in rows] == sorted(r["id"] for r in rows) and len(rows) == 3
    assert json.loads(rows[0]["proof"]) == proof and rows[0]["created_at"] == 10.0


def test_stall_evidence_has_no_proof_and_since_filters(store, req):
    store.add_evidence("STALL", "builder5", req, None, 20.0)
    assert store.list_evidence(0)[0]["proof"] is None
    assert len(store.list_evidence(20.0)) == 1  # inclusive
    assert store.list_evidence(20.1) == []


# --- durability and configuration ------------------------------------------------------------


def test_pragmas(store, path):
    db = store.db
    assert db.execute("PRAGMA synchronous").fetchone()[0] == 2  # FULL
    assert db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    if path != ":memory:":
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_committed_state_survives_a_reopen_and_schema_creation_is_idempotent(
    tmp_path, genesis, attest, release_env
):
    path = str(tmp_path / "matrix.db")
    rid = request_id(release_env["body"])
    s = Store(path)
    s.add_request(rid, release_env, 100.0, "RECEIVED")
    e = parsed(genesis, attest, "builder1", H1)
    s.record_own_attestation(rid, H1, "/a", e, 101.0)
    del s  # no explicit close: simulates a crash after the commit

    s2 = Store(path)
    assert s2.get_request(rid) and s2.get_request(rid)["phase"] == "ATTESTED"
    assert s2.get_build(rid) and s2.get_build(rid)["result"] == H1
    assert s2.attestations(rid) == [e.raw]


def test_requests_with_equal_timestamps_come_back_in_arrival_order(
    store, release_env, keys, genesis
):
    from matrix.model import make_envelope

    ids = []
    for tag in ("v9", "v1", "v5", "v3"):  # ids are hashes, so id order differs from arrival order
        body = {**release_env["body"], "tag": tag}
        env = make_envelope("release", "ci-release", body, keys["ci-release"], genesis)
        ids.append(request_id(body))
        store.add_request(ids[-1], env, 100.0, "RECEIVED")
    assert [r["id"] for r in store.list_requests(0)] == ids
    assert [r["id"] for r in store.live_requests(200.0, 3600)] == ids
