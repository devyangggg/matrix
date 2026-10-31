import asyncio

import pytest
from fakes import FakeBuilder, FakeFault, FakePeers, FakeStore

import matrix.builder as builder_mod
from matrix.builder import BuildEnv, Outcome
from matrix.canon import canonical_json
from matrix.genesis import parse_genesis
from matrix.model import make_envelope, parse_envelope, request_id
from matrix.protocol import Engine
from matrix.select import selected

REPO = "https://github.com/org/hello"
H1, H2 = "a" * 64, "b" * 64
HASH_OK = Outcome("HASH", H1, "/art/" + H1, "ok")


async def until(cond, n=500):
    for _ in range(n):
        if cond():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


class Rig:
    def __init__(self, g, keys, clock, monkeypatch, me, outcomes, fault, gate):
        self.g, self.keys, self.clock, self.me = g, keys, clock, me
        self.log: list = []
        self.store = FakeStore(self.log)
        self.peers = FakePeers(log=self.log)
        self.builder = FakeBuilder(outcomes or [HASH_OK], gate)
        monkeypatch.setattr(builder_mod, "build", self.builder)
        self.fault = fault or FakeFault()
        env = BuildEnv("/tmp/mx", me, 1000, 1000)
        sk = keys[me]
        self.engine = Engine(g, g.node(me), sk, self.store, self.peers, env, self.fault, clock)
        self.tasks: list[asyncio.Task] = []

    def release(self, tag="v1.2.0", signer="ci-release", repo=REPO) -> dict:
        body = {"v": 1, "repo_url": repo, "commit": "1" * 40, "tag": tag}
        return make_envelope("release", signer, body, self.keys[signer], self.g)

    def attest(self, signer, result, rid) -> dict:
        body = {"request_id": rid, "result": result}
        return make_envelope("attest", signer, body, self.keys[signer], self.g)

    async def submit(self, tag="v1.2.0") -> str:
        status, body = await self.engine.on_request(self.release(tag))
        assert status == 202
        return body["id"]

    def start_worker(self):
        self.tasks.append(asyncio.create_task(self.engine.build_worker()))

    def phase(self, rid):
        return self.store.get_request(rid)["phase"]


@pytest.fixture
async def make_rig(genesis, keys, clock, monkeypatch):
    rigs = []

    def make(g=None, me="builder1", outcomes=None, fault=None, gate=None) -> Rig:
        rig = Rig(g or genesis, keys, clock, monkeypatch, me, outcomes, fault, gate)
        rigs.append(rig)
        return rig

    yield make
    for rig in rigs:
        for t in rig.tasks:
            t.cancel()
        await asyncio.gather(*rig.tasks, return_exceptions=True)


# --- on_request ----------------------------------------------------------------------------


async def test_new_request_is_stored_forwarded_and_queued(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    assert rig.phase(rid) == "RECEIVED"
    assert rig.peers.requests_sent == [rig.release()]
    assert rig.engine.queue.get_nowait() == rid
    assert rig.fault.new_requests == 1


async def test_submit_is_idempotent(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    assert await rig.submit() == rid
    assert len(rig.peers.requests_sent) == 1 and rig.engine.queue.qsize() == 1
    assert rig.fault.new_requests == 1


async def test_unselected_builder_only_observes(genesis_dict, make_rig, genesis):
    genesis_dict["replicas"] = 5
    g = parse_genesis(genesis_dict)
    rid = request_id(make_rig(g=g).release()["body"])
    out = next(n.id for n in g.nodes if n.id not in selected(rid, g.nodes, 5))
    rig = make_rig(g=g, me=out)
    assert await rig.submit() == rid
    assert rig.phase(rid) == "OBSERVING" and rig.engine.queue.empty()
    assert len(rig.peers.requests_sent) == 1  # still forwards


@pytest.mark.parametrize(
    "make, status, error",
    [
        (lambda r: r.release(signer="builder1"), 403, "forbidden"),  # builder is no release signer
        (lambda r: r.release(repo="https://github.com/evil/repo"), 403, "forbidden"),
        (lambda r: {**r.release(), "sig": "0" * 128}, 400, "invalid_envelope"),
        (lambda r: r.attest("builder1", H1, "9" * 64), 400, "invalid_envelope"),
        (lambda r: b"garbage", 400, "invalid_envelope"),
        (lambda r: {}, 400, "invalid_envelope"),
        (lambda r: b" " * 5000, 413, "too_large"),
    ],
)
async def test_rejected_requests(make_rig, make, status, error):
    rig = make_rig()
    got = await rig.engine.on_request(make(rig))
    assert (got[0], got[1]["error"]) == (status, error)
    assert not rig.store.requests and not rig.peers.requests_sent


async def test_unknown_signer_is_forbidden(make_rig, keys):
    from nacl.signing import SigningKey

    rig = make_rig()
    body = {"v": 1, "repo_url": REPO, "commit": "1" * 40, "tag": "v1"}
    env = make_envelope("release", "mallory", body, SigningKey(b"\x07" * 32), rig.g)
    assert (await rig.engine.on_request(env))[0] == 403


async def test_ingest_cap_is_20_per_minute(make_rig, clock):
    rig = make_rig()
    for i in range(20):
        assert (await rig.engine.on_request(rig.release(f"v{i}")))[0] == 202
    status, body = await rig.engine.on_request(rig.release("v20"))
    assert (status, body["error"]) == (429, "rate_limited")
    assert (await rig.engine.on_request(rig.release("v0")))[0] == 202  # known: not counted
    clock.advance(61)
    assert (await rig.engine.on_request(rig.release("v20")))[0] == 202


# --- build worker --------------------------------------------------------------------------


async def test_third_request_is_shed(make_rig):
    gate = asyncio.Event()
    rig = make_rig(gate=gate)
    rig.start_worker()
    r1 = await rig.submit("v1")
    await rig.builder.started.wait()  # worker holds r1
    r2 = await rig.submit("v2")  # queued
    r3 = await rig.submit("v3")  # queue full
    assert rig.phase(r3) == "SHED"
    gate.set()
    await until(lambda: rig.phase(r1) == rig.phase(r2) == "ATTESTED")
    assert rig.phase(r3) == "SHED"
    assert [c[0] for c in rig.builder.calls] == [r1, r2]
    assert rig.store.attestation_count(r3, "builder1") == 0


async def test_attestation_is_persisted_before_it_is_broadcast(make_rig):
    rig = make_rig()
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.peers.attests_sent)
    assert rig.log.index(("store", "record_own_attestation")) < rig.log.index(
        ("peers", "broadcast_attest")
    )
    sent, only = rig.peers.attests_sent[0]
    e = parse_envelope(sent, rig.g)
    assert (e.signer, e.body) == ("builder1", {"request_id": rid, "result": H1})
    assert only is None
    assert rig.store.attestations(rid) == [sent]
    assert rig.store.get_build(rid)["artifact_path"] == "/art/" + H1


async def test_failed_outcome_is_attested_as_failed(make_rig):
    rig = make_rig(outcomes=[Outcome("FAILED", "FAILED", None, "compile error")])
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.phase(rid) == "ATTESTED")
    assert rig.store.get_build(rid)["result"] == "FAILED"


@pytest.mark.parametrize("kind", ["BAD_REF", "BAD_RECIPE"])
async def test_bad_ref_and_recipe_abstain_without_retry(make_rig, kind):
    rig = make_rig(outcomes=[Outcome(kind, None, None, "nope")])
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.phase(rid) == "MISSED")
    assert len(rig.builder.calls) == 1
    assert not rig.peers.attests_sent and rig.store.get_build(rid)["error"] == "nope"


async def test_error_retries_twice_then_abstains(make_rig):
    rig = make_rig(outcomes=[Outcome("ERROR", None, None, "docker down")])
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.phase(rid) == "MISSED")
    assert [c[1] for c in rig.builder.calls] == [0, 1, 2]
    assert not rig.peers.attests_sent and rig.store.get_build(rid)["error"] == "docker down"


async def test_error_then_success_attests(make_rig):
    rig = make_rig(outcomes=[Outcome("ERROR", None, None, "flake"), HASH_OK])
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.phase(rid) == "ATTESTED")
    assert [c[1] for c in rig.builder.calls] == [0, 1]


async def test_no_retry_when_ttl_leaves_no_time(make_rig, clock):
    rig = make_rig(outcomes=[Outcome("ERROR", None, None, "flake")])
    rid = await rig.submit()
    clock.advance(rig.g.request_ttl_s - rig.g.build_timeout_s)  # now + timeout == t0 + ttl
    rig.start_worker()
    await until(lambda: rig.phase(rid) == "MISSED")
    assert len(rig.builder.calls) == 1


@pytest.mark.parametrize("exc", [TimeoutError(), RuntimeError("bug")])
async def test_builder_timeout_or_crash_is_an_error_and_worker_survives(make_rig, exc):
    rig = make_rig(outcomes=[exc, exc, exc, HASH_OK])
    rig.start_worker()
    r1 = await rig.submit("v1")
    await until(lambda: rig.phase(r1) == "MISSED")
    r2 = await rig.submit("v2")
    await until(lambda: rig.phase(r2) == "ATTESTED")


async def test_settled_request_is_not_built(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    for who in ("builder2", "builder3", "builder4"):
        assert (await rig.engine.on_attest(rig.attest(who, H1, rid), None))[0] == 202
    assert rig.engine.is_settled(rid)
    rig.start_worker()
    await until(lambda: rig.phase(rid) == "MISSED")
    assert rig.builder.calls == [] and rig.store.get_build(rid)["error"] == "settled"


async def test_lie_and_collude_skip_the_build(make_rig):
    lie = make_rig(fault=FakeFault(mode="lie"))
    lie.start_worker()
    rid = await lie.submit()
    await until(lambda: lie.phase(rid) == "ATTESTED")
    assert lie.builder.calls == [] and lie.store.get_build(rid)["result"] != H1

    collude = make_rig(fault=FakeFault(mode="collude", hash=H2))
    collude.start_worker()
    rid = await collude.submit()
    await until(lambda: collude.phase(rid) == "ATTESTED")
    assert collude.builder.calls == [] and collude.store.get_build(rid)["result"] == H2


async def test_stall_never_attests(make_rig):
    rig = make_rig(fault=FakeFault(mode="stall"))
    rig.start_worker()
    rid = await rig.submit()
    await until(lambda: rig.engine.queue.empty())
    await asyncio.sleep(0)
    assert rig.phase(rid) == "RECEIVED" and rig.builder.calls == [] and not rig.peers.attests_sent


async def test_attest_never_signs_two_results(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    await rig.engine.attest(rid, H1, None)
    await rig.engine.attest(rid, H2, None)
    assert rig.store.get_build(rid)["result"] == H1
    assert len(rig.peers.attests_sent) == 1 and rig.store.attestation_count(rid, "builder1") == 1


async def test_equivocate_sends_conflicting_results_to_disjoint_halves(make_rig):
    rig = make_rig(fault=FakeFault(mode="equivocate"))
    rid = await rig.submit()
    await rig.engine.attest(rid, H1, None)
    (e1, only1), (e2, only2) = rig.peers.attests_sent
    assert e1["body"]["result"] == H1 != e2["body"]["result"]
    assert parse_envelope(e2, rig.g) is not None  # both are validly signed
    assert not set(only1) & set(only2)
    assert set(only1) | set(only2) == {f"builder{i}" for i in range(2, 9)}
    assert rig.store.attestation_count(rid, "builder1") == 1  # only the first is persisted


# --- on_attest -----------------------------------------------------------------------------


async def test_attestation_is_stored_once(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    env = rig.attest("builder3", H1, rid)
    status, body = await rig.engine.on_attest(canonical_json(env), None)
    assert status == 202 and body == {"msg_id": parse_envelope(env, rig.g).msg_id}
    assert (await rig.engine.on_attest(env, None))[0] == 202
    assert rig.store.attestation_count(rid, "builder3") == 1


async def test_third_distinct_attestation_from_one_signer_is_ignored(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    for r in (H1, H2, "c" * 64):
        assert (await rig.engine.on_attest(rig.attest("builder3", r, rid), None))[0] == 202
    assert rig.store.attestation_count(rid, "builder3") == 2


@pytest.mark.parametrize(
    "make, status, error",
    [
        (
            lambda r, rid: {**r.attest("builder3", H1, rid), "sig": "0" * 128},
            400,
            "invalid_envelope",
        ),
        (lambda r, rid: r.release(), 400, "invalid_envelope"),
        (lambda r, rid: b"garbage", 400, "invalid_envelope"),
        (lambda r, rid: b" " * 2000, 413, "too_large"),
        (lambda r, rid: r.attest("builder3", H1, "9" * 64), 409, "unknown_request"),
    ],
)
async def test_rejected_attestations(make_rig, make, status, error):
    rig = make_rig()
    rid = await rig.submit()
    got = await rig.engine.on_attest(make(rig, rid), None)
    assert (got[0], got[1]["error"]) == (status, error)
    assert not rig.store.atts


async def test_attestation_from_non_selected_signer_is_rejected(genesis_dict, make_rig):
    genesis_dict["replicas"] = 5
    g = parse_genesis(genesis_dict)
    rig = make_rig(g=g)
    rid = await rig.submit()
    out = next(n.id for n in g.nodes if n.id not in selected(rid, g.nodes, 5))
    assert (await rig.engine.on_attest(rig.attest(out, H1, rid), None))[0] == 400


async def test_attestation_for_expired_request_is_rejected(make_rig, clock):
    rig = make_rig()
    rid = await rig.submit()
    clock.advance(rig.g.request_ttl_s + 1)
    status, body = await rig.engine.on_attest(rig.attest("builder3", H1, rid), None)
    assert (status, body["error"]) == (409, "expired")


async def test_unknown_request_is_fetched_from_the_hinted_peer(make_rig):
    rig = make_rig()
    release = rig.release()
    rid = request_id(release["body"])
    detail = {"request": release, "phase": "RECEIVED", "received_at": 1.0}
    rig.peers.responses = {"builder2": {f"/v1/requests/{rid}": detail}}
    status, _ = await rig.engine.on_attest(rig.attest("builder3", H1, rid), "builder2")
    assert status == 202 and rig.phase(rid) == "RECEIVED"
    assert rig.store.attestation_count(rid, "builder3") == 1


@pytest.mark.parametrize("hint", [None, "evil", "builder1", "builder5"])
async def test_unknown_request_is_not_fetched_from_bad_hints(make_rig, hint):
    rig = make_rig()
    release = rig.release()
    rid = request_id(release["body"])
    detail = {"request": release, "phase": "RECEIVED", "received_at": 1.0}
    # builder5 answers with a different request than the one asked for; the others never answer
    other = {"request": rig.release("v9"), "phase": "RECEIVED", "received_at": 1.0}
    rig.peers.responses = {
        "evil": {f"/v1/requests/{rid}": detail},
        "builder1": {f"/v1/requests/{rid}": detail},
        "builder5": {f"/v1/requests/{rid}": other},
    }
    status, body = await rig.engine.on_attest(rig.attest("builder3", H1, rid), hint)
    assert (status, body["error"]) == (409, "unknown_request")
    assert rig.store.get_request(rid) is None


async def test_equivocation_is_recorded_as_evidence(make_rig):
    rig = make_rig()
    rid = await rig.submit()
    await rig.engine.on_attest(rig.attest("builder3", H1, rid), None)
    await rig.engine.on_attest(rig.attest("builder3", H2, rid), None)
    (ev,) = rig.store.list_evidence(0)
    assert (ev["kind"], ev["signer"], ev["request_id"]) == ("EQUIVOCATION", "builder3", rid)
    assert ev["proof"].count('"sig"') == 2  # two signed, conflicting envelopes
