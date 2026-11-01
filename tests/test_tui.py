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
LOCAL = "127.0.0.1:7700"
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


INTRO_COLORS = {"purple": 1, "green": 2, "muted": 3, "fade1": 4, "fade2": 5, "text": 6, "blue": 7}


def test_intro_four_phases_and_small_terminal_bounds():
    for rows, cols in [(1, 1), (8, 30), (10, 42), (18, 80), (24, 84), (30, 110)]:
        win = IntroWindow(rows, cols)
        for elapsed in (0, 0.2, 0.7, 1.12, 1.32, 1.7, 1.9):
            _intro_frame(win, elapsed, INTRO_COLORS)
            assert win.cells
            if rows < 10 or cols < 42:
                assert "".join(cell[2] for cell in win.cells) == "[ MATRIX ]"[:cols]
                assert all(cell[3] == INTRO_COLORS["blue"] for cell in win.cells)
                continue
            drawn = "".join(cell[2] for cell in win.cells)
            if elapsed == 0:
                assert "[" in drawn and "]" in drawn
            if elapsed == 0.7:
                assert "█" in drawn and any(cell[3] == INTRO_COLORS["green"] for cell in win.cells)
            if elapsed == 1.32:
                assert "RELEASE" not in drawn  # tagline is spaced, not a logo letter
                assert "R E L E A S E" in drawn
                assert any(
                    "█" in text and attr == INTRO_COLORS["blue"] for _, _, text, attr in win.cells
                )
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
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
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
        assert by_id["builder1"][1:] == ["laptopA", "● UP", "✓", "127.0.0.1:7700"]
        assert by_id["builder6"][3] == "!"
        assert by_id["builder8"][2:] == ["○ DOWN", "?", "127.0.0.1:7707"]
        assert "laptopA · builder1" in str(app.query_one("#dashboard").border_title)
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

    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
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
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
    async with app.run_test() as pilot:
        await pilot.press("e")
        [row] = _cells(app)
        assert row[0] == "DISAGREE" and row[4] == "unverified"
        await pilot.press("enter")
        assert "proof (unverified)" in _text(app, "#extra")


async def test_cli_tui_rejects_a_bad_node_address(tmp_path, genesis_dict):
    from matrix.canon import canonical_json
    from matrix.cli import run

    path = tmp_path / "g.json"
    path.write_bytes(canonical_json(genesis_dict))
    assert run(["--genesis", str(path), "--node", "nobody", "tui"]) == 4


async def test_builders_online_from_signed_hellos(peers, genesis, keys):
    # A founded network: online means a fresh signed hello, and the address is the LAN one from
    # the hello. builder6 still answers /v1/health but its last hello is 20 s old: offline.
    import time

    from matrix.cli import ClientBook
    from matrix.discovery import make_hello

    book = ClientBook(genesis, LOCAL)
    now = time.time()
    book.peers_now = now
    for i in range(1, 7):
        nid = f"builder{i}"
        seq = int((now - (20 if nid == "builder6" else 1)) * 1000)
        book.accept(make_hello(genesis, genesis.node(nid), keys[nid], f"192.168.43.{i}:7700", seq))
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1", book=book)
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause()
        by_id = {r[0]: r for r in _cells(app, "#peers")}
        assert by_id["builder2"][2] == "● UP" and by_id["builder2"][4] == "192.168.43.2:7700"
        assert by_id["builder6"][2] == "○ DOWN"  # stale hello, even though health answers
        assert by_id["builder7"][2] == "○ DOWN"  # never heard from: still listed (not left)
        assert "5 online" in _text(app, "#peers-title")


# --- forms: release, verify and keygen run the CLI code from inside the dashboard ---------------


async def _fill(app, pilot, **values):
    from textual.widgets import Input

    for key, value in values.items():
        app.screen.query_one(f"#f-{key}", Input).value = value
    app.screen.query(Input).last().focus()
    await pilot.press("enter")  # Enter on the last field runs the form
    await pilot.pause()


async def test_release_form_runs_the_release_job_and_shows_its_output(peers, genesis, monkeypatch):
    from matrix import tui

    seen = []

    async def fake_release(a, g, local):
        seen.append((a, g, local))
        print("CERTIFIED " + "a" * 64)
        return 0

    monkeypatch.setattr(tui, "release_job", fake_release)
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("n")
        assert isinstance(app.screen, tui.FormScreen)
        await _fill(app, pilot, tag="v1.2.0", commit="1" * 40)
        await pilot.pause(0.2)
        assert isinstance(app.screen, tui.ResultScreen)
        assert "CERTIFIED" in str(app.screen.query_one("#result-text", Static).render())
        assert "exit 0" in app.screen.query_one("#result").border_title
        [(a, g, local)] = seen
        assert (a.repo, a.tag, a.commit, a.wait, a.out) == (
            genesis.allowed_repos[0],
            "v1.2.0",
            "1" * 40,
            600,
            "dist",
        )
        assert a.output is None and local == LOCAL and g is genesis
        await pilot.press("escape")
        assert app._job is None and not isinstance(app.screen, tui.ResultScreen)


async def test_form_needs_its_required_fields(peers, genesis, monkeypatch):
    from matrix import tui

    async def never(a, g, local):
        raise AssertionError("the job must not start")

    monkeypatch.setattr(tui, "release_job", never)
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("n")
        await _fill(app, pilot, tag="", commit="1" * 40)  # the tag is missing
        assert isinstance(app.screen, tui.FormScreen)
        await pilot.press("escape")
        assert not isinstance(app.screen, tui.FormScreen) and app._job is None


async def test_keygen_form_writes_a_private_key_and_shows_the_public_one(peers, genesis, tmp_path):
    from matrix import tui

    out = tmp_path / "extra.key"
    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("k")
        await _fill(app, pilot, out=str(out))
        await pilot.pause(0.2)
        assert isinstance(app.screen, tui.ResultScreen)
        shown = str(app.screen.query_one("#result-text", Static).render())
        assert len(shown) == 64 and set(shown) <= set("0123456789abcdef")
        assert (out.stat().st_mode & 0o777) == 0o600


async def test_reset_needs_the_typed_confirmation(peers, genesis):
    from matrix import tui

    calls = []

    async def reset():
        calls.append(1)
        return "wiped"

    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1", on_reset=reset)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("x")
        await _fill(app, pilot, confirm="yes")  # not RESET
        await pilot.pause(0.2)
        assert calls == [] and "nothing deleted" in str(
            app.screen.query_one("#result-text", Static).render()
        )
        await pilot.press("escape")
        await pilot.press("x")
        await _fill(app, pilot, confirm="RESET")
        await pilot.pause(0.2)
        assert calls == [1]
        assert isinstance(app.screen, tui.ResultScreen)


async def test_reset_is_refused_without_a_builder_in_process(peers, genesis):
    from matrix import tui

    app = MatrixTui(genesis, LOCAL, peers=peers, local_id="builder1")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.press("x")
        assert not isinstance(app.screen, tui.FormScreen)
