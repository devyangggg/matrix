"""`matrix release`, `status`, `evidence` against 8 aiohttp test servers (RFC §7.11, LLD §3.13).

The servers are dumb: they serve whatever the test puts in `NodeState`, so each test plays the
honest and malicious builders it needs. All attestations are really signed with the test keys.
"""

import asyncio
import hashlib
import json
import threading
from dataclasses import dataclass, field

import pytest
from aiohttp import web

from matrix import cli
from matrix.canon import canonical_json, loads_strict
from matrix.genesis import parse_genesis
from matrix.model import make_envelope, request_id
from tests.conftest import COMMIT, REPO, genesis_raw, seed_for

BINARY = b"\x7fELF honest hello"
H = hashlib.sha256(BINARY).hexdigest()
BODY = {"v": 1, "repo_url": REPO, "commit": COMMIT, "tag": "v1.2.0"}
RID = request_id(BODY)


@dataclass
class NodeState:
    accept: int = 202
    up: bool = True  # False: every GET answers 500
    request: dict | None = None  # served by GET /v1/requests/{id}
    envelopes: list = field(default_factory=list)
    artifacts: dict = field(default_factory=dict)  # sha -> bytes
    evidence: list = field(default_factory=list)
    posted: list = field(default_factory=list)
    artifact_gets: int = 0


def _app(st: NodeState) -> web.Application:
    def down() -> web.Response:
        return web.json_response({"error": "not_found"}, status=500)

    async def post_request(r: web.Request) -> web.Response:
        env = json.loads(await r.read())
        st.posted.append(env)
        st.request = st.request or env
        return web.json_response({"id": request_id(env["body"])}, status=st.accept)

    async def get_request(r: web.Request) -> web.Response:
        if not st.up or st.request is None:
            return down()
        return web.json_response({"request": st.request, "phase": "ATTESTED", "received_at": 1})

    async def bundle(r: web.Request) -> web.Response:
        if not st.up:
            return down()
        return web.json_response({"request": st.request, "envelopes": st.envelopes})

    async def artifact(r: web.Request) -> web.Response:
        st.artifact_gets += 1
        data = st.artifacts.get(r.match_info["sha"])
        if not st.up or data is None:
            return down()
        return web.Response(body=data, content_type="application/octet-stream")

    async def evidence(r: web.Request) -> web.Response:
        return web.json_response({"now": 1, "evidence": st.evidence}) if st.up else down()

    app = web.Application()
    app.router.add_post("/v1/requests", post_request)
    app.router.add_get("/v1/requests/{id}", get_request)
    app.router.add_get("/v1/requests/{id}/bundle", bundle)
    app.router.add_get("/v1/artifacts/{sha}", artifact)
    app.router.add_get("/v1/evidence", evidence)
    return app


class Net:
    def __init__(self, states, g, gpath, keys, tmp):
        self.states, self.g, self.gpath, self.keys, self.tmp = states, g, gpath, keys, tmp
        self.ids = [n.id for n in g.nodes]

    def node(self, nid: str) -> NodeState:
        return self.states[self.ids.index(nid)]

    def att(self, signer: str, result: str, rid: str = RID) -> dict:
        body = {"request_id": rid, "result": result}
        return make_envelope("attest", signer, body, self.keys[signer], self.g)

    def attest(self, results: dict[str, str], on: list[str] | None = None) -> None:
        """Every builder in `on` (default all) serves all of `results` in its bundle."""
        envs = [self.att(s, r) for s, r in results.items()]
        for nid in on or self.ids:
            self.node(nid).envelopes = list(envs)

    def serve(self, nid: str, data: bytes = BINARY) -> None:
        self.node(nid).artifacts[H] = data

    def run(self, *args: str) -> int:
        return cli.run(["--genesis", str(self.gpath), *args])

    def release(self, *extra: str, key: str = "ci-release", wait: str = "5") -> int:
        kpath = self.tmp / f"{key}.key"
        kpath.write_text(seed_for(key).hex() + "\n")
        args = ["release", "--repo", REPO, "--tag", "v1.2.0", "--commit", COMMIT]
        args += ["--key", str(kpath), "--wait", wait, "--out", str(self.tmp / "dist")]
        return self.run(*args, *extra)


@pytest.fixture
def net(tmp_path, keys, monkeypatch):
    monkeypatch.setattr(cli, "RELEASE_POLL_S", 0.01)
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    states = [NodeState() for _ in range(8)]

    async def start():
        runners = []
        for st in states:
            runner = web.AppRunner(_app(st))
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", 0).start()
            runners.append(runner)
        return runners

    runners = asyncio.run_coroutine_threadsafe(start(), loop).result(10)
    raw = genesis_raw()
    for n, r in zip(raw["nodes"], runners):
        n["addr"] = f"127.0.0.1:{r.addresses[0][1]}"
    gpath = tmp_path / "genesis.json"
    gpath.write_bytes(canonical_json(raw))
    yield Net(states, parse_genesis(raw), gpath, keys, tmp_path)

    async def stop():
        for r in runners:
            await r.cleanup()

    asyncio.run_coroutine_threadsafe(stop(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


ALL = [f"builder{i}" for i in range(1, 9)]


def _cert(net: Net) -> dict:
    return loads_strict((net.tmp / "dist" / "hello.matrix.json").read_bytes())


# release: verdict -> exit code


def test_certified_writes_binary_and_verifiable_certificate(net, capsys):
    net.attest(dict.fromkeys(ALL, H))
    net.serve("builder4")
    assert net.release() == 0
    assert (net.tmp / "dist" / "hello").read_bytes() == BINARY
    raw = (net.tmp / "dist" / "hello.matrix.json").read_bytes()
    assert raw == canonical_json(loads_strict(raw))  # canonical JSON on disk
    cert = loads_strict(raw)
    assert cert["genesis_hash"] == net.g.hash and request_id(cert["request"]["body"]) == RID
    assert {a["signer"] for a in cert["attestations"]} == set(ALL)
    assert "CERTIFIED" in capsys.readouterr().out
    # the certificate passes offline verify
    dist = net.tmp / "dist"
    args = ["verify", str(dist / "hello"), "--cert", str(dist / "hello.matrix.json")]
    args += ["--repo", REPO, "--tag", "v1.2.0", "--genesis-sha256", net.g.hash]
    assert net.run(*args) == 0


def test_submits_to_first_node_of_first_three_operators(net):
    net.attest(dict.fromkeys(ALL, H))
    net.serve("builder1")
    assert net.release() == 0
    posted = [nid for nid in ALL if net.node(nid).posted]
    assert posted == ["builder1", "builder3", "builder5"]  # laptopA, laptopB, laptopC
    env = net.node("builder1").posted[0]
    assert env["signer"] == "ci-release" and env["body"] == BODY


def test_build_failed(net):
    net.attest({"builder1": "FAILED", "builder2": "FAILED", "builder3": "FAILED"})
    assert net.release() == 5
    assert not (net.tmp / "dist" / "hello").exists()


def test_not_reproducible(net):
    net.attest({nid: f"{i:064x}" for i, nid in enumerate(ALL)})  # 8 different hashes
    assert net.release() == 2
    assert not (net.tmp / "dist").exists()


def test_pending_timeout(net):
    net.attest({"builder1": H, "builder2": H})  # below threshold 3
    assert net.release(wait="0") == 3


def test_corrupted_artifact_skipped(net, monkeypatch):
    monkeypatch.setattr(cli.random, "shuffle", lambda x: x.sort())  # try builder1 first
    net.attest(dict.fromkeys(ALL, H))
    net.serve("builder1", b"\x00" + BINARY[1:])  # bad-artifact fault
    net.serve("builder2", b"backdoored")
    net.serve("builder3")
    assert net.release() == 0
    assert (net.tmp / "dist" / "hello").read_bytes() == BINARY
    assert net.node("builder1").artifact_gets and net.node("builder2").artifact_gets


def test_no_matching_artifact_is_pending(net):
    net.attest(dict.fromkeys(ALL, H))
    for nid in ALL:
        net.serve(nid, b"corrupt")
    assert net.release(wait="0") == 3
    assert not (net.tmp / "dist").exists()


def test_artifact_only_from_attesting_builders(net):
    net.attest({"builder1": H, "builder2": H, "builder3": H, "builder4": "e" * 64})
    net.serve("builder4")  # builder4 did not attest H, so it is never asked
    assert net.release(wait="0") == 3
    assert net.node("builder4").artifact_gets == 0


def test_disagree_warns_and_is_left_out_of_certificate(net, capsys):
    net.attest({**dict.fromkeys(ALL, H), "builder3": "e" * 64})
    net.serve("builder1")
    assert net.release() == 0
    out = capsys.readouterr().out
    assert "WARNING" in out and "DISAGREE" in out
    assert "builder3" not in {a["signer"] for a in _cert(net)["attestations"]}


def test_equivocator_left_out_of_certificate(net):
    net.attest(dict.fromkeys(ALL, H))
    net.node("builder5").envelopes.append(net.att("builder2", "e" * 64))
    net.serve("builder1")
    assert net.release() == 0
    assert "builder2" not in {a["signer"] for a in _cert(net)["attestations"]}


def test_union_across_bundles(net):
    # no single builder has a quorum; the union of three bundles does
    net.attest({"builder1": H}, on=["builder1"])
    net.attest({"builder2": H}, on=["builder2"])
    net.attest({"builder3": H}, on=["builder3"])
    net.serve("builder2")
    assert net.release() == 0


def test_hostile_bundles_ignored(net):
    net.attest(dict.fromkeys(ALL, H))
    net.node("builder8").envelopes += [
        "junk",
        {"v": 1.5},
        None,
        net.att("builder6", "e" * 64, rid="0" * 64),  # other request
    ]
    net.serve("builder1")
    assert net.release() == 0


def test_attestations_for_other_request_do_not_count(net):
    for nid in ALL:
        net.node(nid).envelopes = [net.att(s, H, rid="0" * 64) for s in ALL]
    assert net.release(wait="0") == 3


def test_fewer_than_f_plus_1_builders_answered(net):
    net.attest({"builder1": H, "builder2": H, "builder3": H}, on=["builder1", "builder2"])
    for nid in ALL[2:]:
        net.node(nid).up = False
    net.serve("builder1")
    assert net.release(wait="0") == 4
    assert not (net.tmp / "dist").exists()


# release: errors -> 4


def test_no_builder_accepts(net):
    for st in net.states:
        st.accept = 503
    assert net.release() == 4


def test_one_acceptance_is_enough(net):
    for nid in ("builder3", "builder5"):
        net.node(nid).accept = 400
    net.attest(dict.fromkeys(ALL, H))
    net.serve("builder1")
    assert net.release() == 0


def test_key_not_a_release_signer(net):
    assert net.release(key="builder1") == 4
    assert not any(st.posted for st in net.states)


def test_unreadable_key(net):
    args = ["release", "--repo", REPO, "--tag", "v1", "--commit", COMMIT, "--key", "/nope"]
    assert net.run(*args) == 4


def test_repo_not_allowed(net):
    (net.tmp / "k").write_text(seed_for("ci-release").hex())
    args = ["release", "--repo", "https://github.com/evil/x", "--tag", "v1", "--commit", COMMIT]
    assert net.run(*args, "--key", str(net.tmp / "k")) == 4


def test_bad_commit(net):
    (net.tmp / "k").write_text(seed_for("ci-release").hex())
    args = ["release", "--repo", REPO, "--tag", "v1", "--commit", "abc", "--key"]
    assert net.run(*args, str(net.tmp / "k")) == 4


@pytest.mark.parametrize("name", ["../evil", "a/b", "..", ""])
def test_bad_output_name(net, name):
    assert net.release("--output", name) == 4


def test_output_name(net):
    net.attest(dict.fromkeys(ALL, H))
    net.serve("builder1")
    assert net.release("--output", "hello-linux-amd64") == 0
    assert (net.tmp / "dist" / "hello-linux-amd64.matrix.json").exists()


# status


def _status_env(net: Net) -> dict:
    return make_envelope("release", "ci-release", BODY, net.keys["ci-release"], net.g)


def test_status_agreed(net, capsys):
    net.node("builder2").request = _status_env(net)
    net.attest(dict.fromkeys(ALL[:3], H))
    assert net.run("status", RID) == 0
    out = capsys.readouterr().out
    assert "AGREED" in out and "v1.2.0" in out


def test_status_pending(net):
    net.node("builder2").request = _status_env(net)
    assert net.run("status", RID) == 3


def test_status_ignores_request_that_does_not_hash_to_id(net):
    other = {**BODY, "tag": "v6.6.6"}
    for st in net.states:
        st.request = make_envelope("release", "ci-release", other, net.keys["ci-release"], net.g)
    assert net.run("status", RID) == 4


def test_status_unknown_and_bad_id(net):
    assert net.run("status", RID) == 4
    assert net.run("status", "../../etc") == 4


# evidence


def _equivocation(net: Net) -> dict:
    proof = [net.att("builder2", H), net.att("builder2", "e" * 64)]
    item = {"kind": "EQUIVOCATION", "signer": "builder2", "request_id": RID, "proof": proof}
    return {"id": 1, "created_at": 1, **item}


def test_evidence_dedupes_and_checks_proof(net, capsys):
    ev = _equivocation(net)
    net.node("builder1").evidence = [ev]
    net.node("builder3").evidence = [ev, {**ev, "id": 7}]
    forged = {**ev, "signer": "builder6", "proof": [ev["proof"][0], ev["proof"][0]]}
    net.node("builder4").evidence = [forged, "junk", {"kind": 1}]
    assert net.run("evidence", "--since", "1h") == 0
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("EQUIVOCATION")]
    assert len(lines) == 2
    assert "builder2" in lines[0] and "proof-ok" in lines[0]
    assert "builder6" in lines[1] and "no-proof" in lines[1]


def test_evidence_no_builder_answers(net):
    for st in net.states:
        st.up = False
    assert net.run("evidence") == 4


def test_evidence_bad_since(net):
    assert net.run("evidence", "--since", "yesterday") == 4


def test_check_proof(net):
    ev = _equivocation(net)
    assert cli.check_proof(ev, net.g)
    assert not cli.check_proof({**ev, "proof": [ev["proof"][0]] * 2}, net.g)  # same result
    assert not cli.check_proof({**ev, "request_id": "0" * 64}, net.g)
    assert not cli.check_proof({**ev, "proof": None}, net.g)
    assert not cli.check_proof({**ev, "proof": [{"sig": "x"}, 3]}, net.g)
