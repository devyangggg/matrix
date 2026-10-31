"""TUI polling (FakePeers) and the four screens, driven headless with Textual's pilot."""

import pytest
from fakes import FakePeers
from textual.widgets import DataTable, Static

from matrix.model import request_id
from matrix.tui import (
    MatrixTui,
    _intro,
    _intro_frame,
    poll_evidence,
    poll_health,
    poll_log,
    poll_releases,
)

H = "a" * 64
OTHER = "e" * 64


class IntroWindow:
    def __init__(self, rows, cols, key=-1):
        self.rows, self.cols, self.key = rows, cols, key
        self.cells = []
        self.reads = 0

    def getmaxyx(self):
        return self.rows, self.cols

    def erase(self):
        self.cells = []

    def addstr(self, y, x, text, attr):
        assert 0 <= y < self.rows and 0 <= x < self.cols
        assert x + len(text) <= self.cols
        self.cells.append((y, x, text, attr))

    def getch(self):
        self.reads += 1
        return self.key

    def nodelay(self, value):
        assert value

    def keypad(self, value):
        assert value

    def refresh(self):
        pass


INTRO_COLORS = {"purple": 1, "green": 2, "muted": 3, "fade1": 4, "fade2": 5, "text": 6}


def test_intro_four_phases_and_small_terminal_bounds():
    for rows, cols in [(1, 1), (8, 30), (10, 42), (18, 80), (24, 84), (30, 110)]:
        win = IntroWindow(rows, cols)
        for elapsed in (0, 0.2, 0.7, 1.12, 1.32, 1.7, 1.9):
            _intro_frame(win, elapsed, INTRO_COLORS)
            assert win.cells
            if rows < 10 or cols < 42:
                assert "".join(cell[2] for cell in win.cells) == "[ MATRIX ]"[:cols]
                continue
            drawn = "".join(cell[2] for cell in win.cells)
            if elapsed == 0:
                assert "[" in drawn and "]" in drawn
            if elapsed == 0.7:
                assert "█" in drawn and any(cell[3] == INTRO_COLORS["green"] for cell in win.cells)
            if elapsed == 1.32:
                assert "RELEASE" not in drawn  # tagline is spaced, not a logo letter
                assert "R E L E A S E" in drawn
            if elapsed == 1.9:
                assert "▒" in drawn or "░" in drawn


def test_tagline_fades_from_muted_to_primary():
    win = IntroWindow(24, 84)
    for elapsed, colour in (
        (1.13, "muted"),
        (1.23, "fade1"),
        (1.32, "fade2"),
        (1.42, "text"),
    ):
        _intro_frame(win, elapsed, INTRO_COLORS)
        assert (
            next(attr for _, _, text, attr in win.cells if "R E L E A S E" in text)
            == (INTRO_COLORS[colour])
        )


def test_any_key_skips_intro_immediately(monkeypatch):
    from matrix import tui

    monkeypatch.setattr(tui.curses, "curs_set", lambda _: None)
    monkeypatch.setattr(tui, "_intro_colors", lambda: INTRO_COLORS)
    win = IntroWindow(24, 84, key=ord("x"))
    _intro(win)
    assert win.reads == 1 and win.cells == []


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
            f"/v1/requests/{rid}": {"request": release_env},
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
    peers.responses["builder1"][f"/v1/requests/{rid}"]["request"] = swapped
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.verdict.state == "INVALID" and r.body is None


async def test_poll_releases_ignores_bundle_request_substitution(peers, genesis, rid, keys):
    from matrix.model import make_envelope

    body = {"v": 1, "repo_url": "https://github.com/org/hello", "commit": "2" * 40, "tag": "x"}
    swapped = make_envelope("release", "ci-release", body, keys["ci-release"], genesis)
    peers.responses["builder1"][f"/v1/requests/{rid}/bundle"]["request"] = swapped
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.body["tag"] == "v1.2.0"
    assert r.verdict.state == "AGREED" and r.verdict.hash == H


async def test_poll_releases_missing_bundle_is_invalid_not_pending(peers, genesis, rid):
    del peers.responses["builder1"][f"/v1/requests/{rid}/bundle"]
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.body["tag"] == "v1.2.0"
    assert r.verdict.state == "INVALID"


async def test_poll_releases_rejects_bad_signature(peers, genesis, rid):
    request = peers.responses["builder1"][f"/v1/requests/{rid}"]["request"]
    peers.responses["builder1"][f"/v1/requests/{rid}"]["request"] = {
        **request,
        "sig": "0" * 128,
    }
    [r] = await poll_releases(peers, genesis, "builder1")
    assert r.body is None and r.verdict.state == "INVALID"


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


def _cells(app: MatrixTui, panel: str = "#table") -> list[list[str]]:
    t = app.query_one(panel, DataTable)
    return [[str(c) for c in t.get_row_at(i)] for i in range(t.row_count)]


def _text(app: MatrixTui, wid: str) -> str:
    return str(app.query_one(wid, Static).render())


async def test_three_box_dashboard_and_shortcuts(peers, genesis, rid):
    app = MatrixTui(genesis, "builder1", peers=peers)
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause()
        left, right, bottom = (
            app.query_one(f"#{panel}")
            for panel in ("peers-panel", "requests-panel", "details-panel")
        )
        assert left.region.y == right.region.y and left.region.x < right.region.x
        assert bottom.region.y > left.region.y and bottom.region.width > left.region.width
        assert "┴" in _text(app, "#divider")
        assert "PEERS (8)" in _text(app, "#peers-title")
        assert "REQUESTS" in _text(app, "#requests-title")

        rows = _cells(app, "#peers")
        assert len(rows) == 8
        by_id = {r[0]: r for r in rows}
        assert by_id["builder1"][1:] == ["laptopA", "● UP", "✓"]
        assert by_id["builder6"][3] == "!"
        assert by_id["builder8"][2:] == ["○ DOWN", "?"]
        [request] = _cells(app)
        assert rid[:8] in request[0] and "hello@v1.2.0" in request[0]
        assert "ATTESTED" in request[0]
        assert request[1:] == ["6/8", "3/3", f"AGREED {H[:12]}"]
        details = _text(app, "#details")
        assert "builder1" in details and "MATCH" in details
        assert "builder3" in details and "DISAGREES" in details
        assert "builder2" in details and "EQUIVOCATION" in details
        assert "builder7" in details and "NO ATTESTATION" in details
        assert "VERDICT: AGREED" in details and "THRESHOLD: 3" in details
        await pilot.press("r", "enter", "l")
        await pilot.pause()
        assert app.view == "detail" and rid[:8] in _text(app, "#details-title")
        assert "go build" in _text(app, "#extra")

        await pilot.press("e")
        [ev] = _cells(app)
        assert "EVIDENCE" in _text(app, "#requests-title")
        assert ev[0] == "EQUIVOCATION" and ev[1] == "builder2" and ev[4] == "valid"
        await pilot.press("enter")
        assert "proof (valid)" in _text(app, "#extra") and OTHER in _text(app, "#extra")

        await pilot.press("b")
        assert len(_cells(app, "#peers")) == 8
        assert "REQUESTS" in _text(app, "#requests-title")


async def test_selected_release_updates_details_and_resizes(peers, genesis, release_env, keys, rid):
    from matrix.model import make_envelope

    other_body = {**release_env["body"], "commit": "2" * 40, "tag": "v1.2.1"}
    other = make_envelope("release", "ci-release", other_body, keys["ci-release"], genesis)
    other_id = request_id(other_body)
    peers.responses["builder1"]["/v1/requests?since=0"]["requests"].append(
        {"id": other_id, "phase": "BUILDING", "received_at": 0}
    )
    peers.responses["builder1"][f"/v1/requests/{other_id}"] = {"request": other}
    peers.responses["builder1"][f"/v1/requests/{other_id}/bundle"] = {"envelopes": []}

    app = MatrixTui(genesis, "builder1", peers=peers)
    async with app.run_test(size=(50, 14)) as pilot:
        await pilot.press("r", "down")
        assert other_id[:8] in _text(app, "#details-title")
        assert "PENDING" in _text(app, "#details")
        await pilot.resize_terminal(110, 30)
        await pilot.pause()
        assert other_id[:8] in _text(app, "#details-title")
        assert "THRESHOLD: 3" in _text(app, "#details")
        assert "┴" in _text(app, "#divider")
        await pilot.press("up", "enter")
        assert app.view == "detail" and rid[:8] in _text(app, "#details-title")


async def test_evidence_disagree_single_vote_is_unverified(peers, genesis, rid):
    signed_vote = peers.responses["builder1"][f"/v1/requests/{rid}/bundle"]["envelopes"][0]
    peers.responses["builder1"]["/v1/evidence?since=0"]["evidence"] = [
        {
            "kind": "DISAGREE",
            "signer": signed_vote["signer"],
            "request_id": rid,
            "proof": [signed_vote],
        }
    ]
    app = MatrixTui(genesis, "builder1", peers=peers)
    async with app.run_test() as pilot:
        await pilot.press("e")
        [row] = _cells(app)
        assert row[0] == "DISAGREE" and row[4] == "unverified"
        await pilot.press("enter")
        assert "proof (unverified)" in _text(app, "#extra")


async def test_cli_tui_rejects_unknown_node(tmp_path, genesis_dict):
    from matrix.canon import canonical_json
    from matrix.cli import run

    path = tmp_path / "g.json"
    path.write_bytes(canonical_json(genesis_dict))
    assert run(["--genesis", str(path), "tui", "--node", "nobody"]) == 4
