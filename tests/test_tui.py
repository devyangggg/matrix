"""Textual views consume real HTTP routes and recompute trust from signed envelopes."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from fakes import FakePeers, FakeStore
from textual.widgets import DataTable

from matrix.builder import BuildEnv
from matrix.faults import Fault
from matrix.model import make_envelope, request_id
from matrix.net import make_app
from matrix.protocol import Engine
from matrix.tui import MatrixApp

HASH = "a" * 64
OTHER = "b" * 64


@pytest.fixture
async def live_api(tmp_path, genesis, keys, release_env):
    store = FakeStore()
    me = genesis.nodes[0]
    engine = Engine(
        genesis,
        me,
        keys[me.id],
        store,
        FakePeers(),
        BuildEnv(str(tmp_path), me.id, 1000, 1000),
        Fault(),
    )
    server = TestServer(
        make_app(engine, store, genesis, me, SimpleNamespace(data_dir=str(tmp_path)))
    )
    await server.start_server()
    address = f"127.0.0.1:{server.port}"
    ui_genesis = replace(
        genesis,
        nodes=(
            replace(me, addr=address),
            *(replace(n, addr="127.0.0.1:0") for n in genesis.nodes[1:]),
        ),
    )
    rid = request_id(release_env["body"])
    status, _ = await engine.on_request(release_env)
    assert status == 202
    try:
        yield ui_genesis, engine, store, server, rid, tmp_path
    finally:
        await server.close()


@pytest.mark.asyncio
async def test_live_views_and_late_equivocation(live_api, attest):
    g, engine, _, server, rid, directory = live_api
    for signer in ("builder1", "builder2", "builder3"):
        assert (await engine.on_attest(attest(signer, HASH), None))[0] == 202
    log = directory / "logs" / f"{rid}.log"
    log.parent.mkdir()
    log.write_text("actual local build log\n")
    app = MatrixApp(g, g.nodes[0])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await app.refresh_snapshot()
        assert app.health["builder1"][0] == "yes"
        assert app.health["builder2"][0] == "unreachable"
        await pilot.press("r")
        assert app.releases[0].verdict.state == "AGREED"
        assert "3/3" in app.query_one(DataTable).get_row_at(0)
        await pilot.press("enter")
        assert app.view == "detail"
        rows = app.query_one(DataTable)
        builder1 = next(i for i in range(rows.row_count) if rows.get_row_at(i)[0] == "builder1")
        assert rows.get_row_at(builder1)[2] == "yes"
        await pilot.press("l")
        assert app.log_text == "actual local build log\n"
        # A second signed result from builder1 removes its earlier vote on the next poll.
        assert (await engine.on_attest(attest("builder1", OTHER), None))[0] == 202
        await app.refresh_snapshot()
        assert app.releases[0].verdict.state == "PENDING"
        assert app.query_one(DataTable).get_row_at(builder1)[1] == "EQUIVOCATED"
        await pilot.press("e")
        assert any(item["kind"] == "EQUIVOCATION" for item in app.evidence)
        await pilot.press("enter")
        assert app.view == "proof"
        assert app.proof["kind"] == "EQUIVOCATION"
        assert len(app.proof["proof"]) == 2
        await server.close()
        await app.refresh_snapshot()
        assert app.proof is None
        assert app.query_one("#content").render() == "Evidence unavailable"


@pytest.mark.asyncio
async def test_untrusted_request_never_borrows_bundle_vote(live_api, attest, release_env, keys):
    g, engine, store, server, rid, _ = live_api
    for signer in ("builder1", "builder2", "builder3"):
        await engine.on_attest(attest(signer, HASH), None)
    app = MatrixApp(g, g.nodes[0])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await app.refresh_snapshot()
        assert app.releases[0].verdict.state == "AGREED"
        forged = json.loads(store.requests[rid]["envelope"])
        forged["sig"] = "0" * 128
        store.requests[rid]["envelope"] = json.dumps(forged)
        await app.refresh_snapshot()
        await pilot.press("r")
        assert app.releases[0].verdict.state == "INVALID"
        assert "unverified" in app.query_one(DataTable).get_row_at(0)
        other_body = {**release_env["body"], "tag": "v1.2.1"}
        store.requests[rid]["envelope"] = json.dumps(
            make_envelope("release", "ci-release", other_body, keys["ci-release"], g)
        )
        await app.refresh_snapshot()
        assert app.releases[0].verdict.state == "INVALID"
        # A failed refresh must not leave a previously certified view on screen.
        await server.close()
        await app.refresh_snapshot()
        assert app.releases == []
        assert app.online is False
        assert app.query_one(DataTable).row_count == 0


@pytest.mark.asyncio
async def test_refresh_preserves_navigation_position(live_api, keys, release_env):
    g, engine, _, _, _, _ = live_api
    second_body = {**release_env["body"], "tag": "v1.2.1"}
    second = make_envelope("release", "ci-release", second_body, keys["ci-release"], g)
    await engine.on_request(second)
    app = MatrixApp(g, g.nodes[0])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        await app.refresh_snapshot()
        await pilot.press("r")
        table = app.query_one(DataTable)
        assert table.row_count == 2
        table.move_cursor(row=1)
        await app.refresh_snapshot()
        assert table.cursor_row == 1
        await pilot.press("enter")
        assert app.selected_id == request_id(second_body)


@pytest.mark.asyncio
async def test_duplicate_fields_in_http_response_are_rejected(genesis):
    async def ambiguous(_request):
        return web.Response(
            text='{"requests":[],"requests":[{"id":"' + "a" * 64 + '"}]}',
            content_type="application/json",
        )

    api = web.Application()
    api.router.add_get("/v1/requests", ambiguous)
    server = TestServer(api)
    await server.start_server()
    me = replace(genesis.nodes[0], addr=f"127.0.0.1:{server.port}")
    g = replace(genesis, nodes=(me, *genesis.nodes[1:]))
    try:
        app = MatrixApp(g, me)
        async with app.run_test() as pilot:
            await pilot.pause(0.2)
            await app.refresh_snapshot()
            assert app.online is False
            assert app.releases == []
    finally:
        await server.close()
