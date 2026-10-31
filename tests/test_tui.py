"""TUI polling (FakePeers) and the four screens, driven headless with Textual's pilot."""

import pytest
from fakes import FakePeers
from textual.widgets import DataTable, Static

from matrix.model import request_id
from matrix.tui import MatrixTui, poll_evidence, poll_health, poll_log, poll_releases

H = "a" * 64
OTHER = "e" * 64


@pytest.fixture
def rid(release_env):
    return request_id(release_env["body"])


@pytest.fixture
def peers(genesis, release_env, attest, rid):
    """builder1 knows one release: 7 honest votes, builder3 disagrees, builder2 equivocates."""
    atts = [attest(s, H) for s in ("builder1", "builder2", "builder4", "builder5", "builder6")]
    atts += [attest("builder3", OTHER), attest("builder2", OTHER)]
    health = {
        n.id: {"node_id": n.id, "version": "0.1.0", "genesis_hash": genesis.hash, "now": 1}
        for n in genesis.nodes[:6]
    }
    health["builder6"]["genesis_hash"] = "0" * 64  # misconfigured builder
    proof = [attest("builder2", H), attest("builder2", OTHER)]
    ev = {"id": 1, "kind": "EQUIVOCATION", "signer": "builder2", "request_id": rid}
    responses = {nid: {"/v1/health": h} for nid, h in health.items()}
    responses["builder1"].update(
        {
            "/v1/requests?since=0": {
                "now": 2,
                "requests": [{"id": rid, "phase": "ATTESTED", "received_at": 1}, "junk"],
            },
            f"/v1/requests/{rid}/bundle": {"request": release_env, "envelopes": atts},
            f"/v1/requests/{rid}/log": b"go build ./cmd/hello\nok\n",
            "/v1/evidence?since=0": {
                "now": 2,
                "evidence": [{**ev, "proof": proof, "created_at": 1}, {"kind": 3}],
            },
        }
    )
    return FakePeers(responses)


async def test_poll_health(peers, genesis):
    h = await poll_health(peers, genesis)
    assert h["builder1"]["node_id"] == "builder1"
    assert h["builder7"] is None and h["builder8"] is None


async def test_poll_releases_runs_verdict_locally(peers, genesis, rid):
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.id == rid and r.body["tag"] == "v1.2.0" and r.phase == "ATTESTED"
    assert r.verdict.state == "AGREED" and r.verdict.hash == H
    assert r.verdict.equivocators == {"builder2"}
    assert r.counts() == (6, 4)  # 5 single-result signers + 1 equivocator; 4 agree on H


async def test_poll_releases_rejects_request_with_wrong_id(peers, genesis, rid, keys):
    from matrix.model import make_envelope

    body = {"v": 1, "repo_url": "https://github.com/org/hello", "commit": "2" * 40, "tag": "x"}
    swapped = make_envelope("release", "ci-release", body, keys["ci-release"], genesis)
    peers.responses["builder1"][f"/v1/requests/{rid}/bundle"]["request"] = swapped
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.verdict.state == "INVALID" and r.body is None


async def test_poll_releases_unreachable_or_garbage(peers, genesis):
    assert await poll_releases(peers, genesis, "builder8") == []
    peers.responses["builder1"]["/v1/requests?since=0"] = {"requests": "nope"}
    assert await poll_releases(peers, genesis, "builder1") == []


async def test_poll_evidence_drops_junk(peers):
    [e] = await poll_evidence(peers, "builder1")
    assert e["kind"] == "EQUIVOCATION"
    assert await poll_evidence(peers, "builder8") == []


async def test_poll_log(peers, rid):
    assert "go build" in await poll_log(peers, "builder1", rid)
    assert "no log" in await poll_log(peers, "builder2", rid)


def _cells(app: MatrixTui) -> list[list[str]]:
    t = app.query_one("#table", DataTable)
    return [[str(c) for c in t.get_row_at(i)] for i in range(t.row_count)]


def _text(app: MatrixTui, wid: str) -> str:
    return str(app.query_one(wid, Static).render())


async def test_screens(peers, genesis, rid):
    app = MatrixTui(genesis, "builder1", peers=peers)
    async with app.run_test() as pilot:
        await pilot.pause()
        rows = _cells(app)  # Builders
        assert len(rows) == 8
        by_id = {r[1]: r for r in rows}
        assert by_id["builder1"][3:5] == ["yes", "match"]
        assert by_id["builder6"][4] == "MISMATCH"
        assert by_id["builder8"][3] == "no"

        await pilot.press("r")  # Releases
        [row] = _cells(app)
        assert row[0] == rid[:12] and row[1] == "hello@v1.2.0"
        assert row[3:5] == ["6/8", "3/3"] and row[5].startswith("AGREED")

        await pilot.press("enter")  # Detail
        marks = {r[0]: r[3] for r in _cells(app)}
        assert marks["builder1"] == "ok" and marks["builder3"] == "DISAGREE"
        assert marks["builder2"] == "EQUIVOCATION" and marks["builder7"] == "-"

        await pilot.press("l")
        await pilot.pause()
        assert "go build" in _text(app, "#extra")

        await pilot.press("e")  # Evidence
        [ev] = _cells(app)
        assert ev[0] == "EQUIVOCATION" and ev[1] == "builder2" and ev[4] == "valid"
        await pilot.press("enter")
        assert "proof (valid)" in _text(app, "#extra") and OTHER in _text(app, "#extra")

        await pilot.press("b")
        assert len(_cells(app)) == 8


async def test_cli_tui_rejects_unknown_node(tmp_path, genesis_dict):
    from matrix.canon import canonical_json
    from matrix.cli import run

    path = tmp_path / "g.json"
    path.write_bytes(canonical_json(genesis_dict))
    assert run(["--genesis", str(path), "tui", "--node", "nobody"]) == 4
