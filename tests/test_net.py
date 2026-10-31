"""HTTP surfaces use untrusted bytes and only stored, validated paths."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from matrix.net import PeerClient, make_app
from matrix.node import _fault, _parser, main

RID = "a" * 64
HASH = "b" * 64


class FakeEngine:
    def __init__(self):
        self.requests = []
        self.messages = []
        self.fault = SimpleNamespace(corrupt_artifacts=False)
        self.clock = lambda: 100.0
        self.request_status = (202, {"id": RID})
        self.message_status = (202, {"msg_id": HASH})

    async def on_request(self, raw):
        self.requests.append(raw)
        return self.request_status

    async def on_attest(self, raw, from_hint):
        self.messages.append((raw, from_hint))
        return self.message_status


class FakeStore:
    def __init__(self, data):
        self.data = data
        self.envelopes = [{"type": "attest"}]
        self.path = None

    def get_request(self, rid):
        return self.data if rid == RID else None

    def list_requests(self, since):
        return [self.data] if since <= self.data["received_at"] else []

    def attestations(self, rid):
        return self.envelopes

    def list_evidence(self, since):
        return (
            [
                {
                    "id": 1,
                    "kind": "STALL",
                    "signer": "builder2",
                    "request_id": RID,
                    "proof": None,
                    "created_at": 10.0,
                }
            ]
            if since <= 10
            else []
        )

    def artifact_path(self, sha):
        return self.path if sha == HASH else None


@pytest_asyncio.fixture
async def api(tmp_path):
    engine = FakeEngine()
    store = FakeStore(
        {
            "id": RID,
            "phase": "RECEIVED",
            "received_at": 10.0,
            "envelope": json.dumps({"type": "release"}),
        }
    )
    me = SimpleNamespace(id="builder1", addr="127.0.0.1:7700")
    g = SimpleNamespace(hash="c" * 64, nodes=[me], node=lambda node_id: me)
    env = SimpleNamespace(data_dir=str(tmp_path))
    client = TestClient(TestServer(make_app(engine, store, g, me, env)))
    await client.start_server()
    try:
        yield client, engine, store, tmp_path
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_health_and_request_routes(api):
    client, engine, store, _ = api
    response = await client.get("/v1/health")
    assert response.status == 200
    assert (await response.json())["genesis_hash"] == "c" * 64
    response = await client.post("/v1/requests", data=b"signed request")
    assert response.status == 202
    assert await response.json() == {"id": RID}
    assert engine.requests == [b"signed request"]
    for status, code in [
        (400, "invalid_envelope"),
        (403, "forbidden"),
        (429, "rate_limited"),
    ]:
        engine.request_status = (status, {"error": code})
        response = await client.post("/v1/requests", data=b"x")
        assert (response.status, (await response.json())["error"]) == (status, code)
    response = await client.post("/v1/requests", data=b"x" * 4097)
    assert (response.status, (await response.json())["error"]) == (413, "too_large")
    assert len(engine.requests) == 4
    response = await client.get("/v1/requests?since=11")
    assert (await response.json())["requests"] == []
    response = await client.get("/v1/requests?since=10")
    assert (await response.json())["requests"] == [
        {"id": RID, "phase": "RECEIVED", "received_at": 10.0}
    ]
    response = await client.get(f"/v1/requests/{RID}")
    assert (await response.json())["request"] == {"type": "release"}
    response = await client.get(f"/v1/requests/{RID}/bundle")
    assert (await response.json())["envelopes"] == store.envelopes
    for suffix in ["", "/bundle", "/log"]:
        response = await client.get(f"/v1/requests/INVALID{suffix}")
        assert response.status == 404


@pytest.mark.asyncio
async def test_messages_logs_artifacts_and_evidence(api):
    client, engine, store, tmp = api
    response = await client.post(
        "/v1/messages", data=b"attestation", headers={"X-Matrix-From": "builder2"}
    )
    assert response.status == 202
    assert engine.messages == [(b"attestation", "builder2")]
    for status, code in [
        (400, "invalid_envelope"),
        (409, "unknown_request"),
        (409, "expired"),
    ]:
        engine.message_status = (status, {"error": code})
        response = await client.post("/v1/messages", data=b"x")
        assert (response.status, (await response.json())["error"]) == (status, code)
    response = await client.post("/v1/messages", data=b"x" * 1025)
    assert (response.status, (await response.json())["error"]) == (413, "too_large")
    assert len(engine.messages) == 4
    assert (await client.get(f"/v1/requests/{RID}/log")).status == 404
    log = tmp / "logs" / f"{RID}.log"
    log.parent.mkdir()
    log.write_bytes(b"q" * 70000 + b"last")
    response = await client.get(f"/v1/requests/{RID}/log")
    assert response.status == 200
    assert (await response.read()) == b"q" * (65536 - 4) + b"last"
    assert (await client.get("/v1/artifacts/INVALID")).status == 404
    assert (await client.get(f"/v1/artifacts/{HASH}")).status == 404
    artifact = tmp / "artifact"
    artifact.write_bytes(b"honest binary")
    store.path = str(artifact)
    response = await client.get(f"/v1/artifacts/{HASH}")
    assert (response.status, await response.read()) == (200, b"honest binary")
    engine.fault.corrupt_artifacts = True
    response = await client.get(f"/v1/artifacts/{HASH}")
    assert (response.status, await response.read()) == (
        200,
        bytes([ord("h") ^ 255]) + b"onest binary",
    )
    response = await client.get("/v1/evidence?since=11")
    assert (await response.json())["evidence"] == []
    response = await client.get("/v1/evidence")
    assert (await response.json())["evidence"][0]["proof"] is None


@pytest.mark.asyncio
async def test_peer_client_posts_hint_and_bounds_download(api):
    client, engine, store, tmp = api
    address = client.make_url("/").host + ":" + str(client.make_url("/").port)
    me = SimpleNamespace(id="builder1")
    peer = SimpleNamespace(id="builder2", addr=address)
    g = SimpleNamespace(nodes=[me, peer], node=lambda node_id: peer if node_id == peer.id else me)
    peers = PeerClient(g, me)
    try:
        await peers.broadcast_request({"hello": "world"})
        # Canonical encoding fits the 1 KiB wire cap; default JSON whitespace would not.
        await peers.broadcast_attest({"x": "a" * 1016})
        await peers.broadcast_attest({"hello": "world"}, only=["builder2"])
        assert await peers.get_json("builder2", "/v1/health") is not None
        assert await peers.get_json("builder1", "/v1/health") is None
        artifact = Path(tmp / "artifact")
        artifact.write_bytes(b"hello")
        store.path = str(artifact)
        assert await peers.get_bytes("builder2", f"/v1/artifacts/{HASH}", 4) is None
        assert await peers.get_bytes("builder2", f"/v1/artifacts/{HASH}", 5) == b"hello"
    finally:
        await peers.close()
    assert engine.requests == [b'{"hello":"world"}']
    assert len(engine.messages) == 2
    assert set(engine.messages) == {
        (b'{"hello":"world"}', "builder1"),
        (b'{"x":"' + b"a" * 1016 + b'"}', "builder1"),
    }


@pytest.mark.asyncio
async def test_peer_json_rejects_oversize_duplicates_and_nonfinite():
    responses = {
        "oversize": b'{"value":"' + b"x" * (1024 * 1024) + b'"}',
        "duplicate": b'{"items":[{"now":1,"now":2}]}',
        "nan": b'{"now":NaN}',
        "infinity": b'{"now":Infinity}',
        "overflow": b'{"now":1e999}',
        "finite": b'{"now":1234.5,"items":[{"received_at":1234.25}]}',
    }
    app = web.Application()
    for name, body in responses.items():

        async def reply(request, payload=body):
            return web.Response(body=payload, content_type="application/json")

        app.router.add_get(f"/{name}", reply)
    client = TestClient(TestServer(app))
    await client.start_server()
    address = f"{client.make_url('/').host}:{client.make_url('/').port}"
    me = SimpleNamespace(id="builder1")
    peer = SimpleNamespace(id="builder2", addr=address)
    peers = PeerClient(SimpleNamespace(node=lambda node_id: peer), me)
    try:
        for name in ("oversize", "duplicate", "nan", "infinity", "overflow"):
            assert await peers.get_json(peer.id, f"/{name}") is None
        assert await peers.get_json(peer.id, "/finite") == {
            "now": 1234.5,
            "items": [{"received_at": 1234.25}],
        }
    finally:
        await peers.close()
        await client.close()


def test_node_rejects_fault_flags_without_opt_in(tmp_path, capsys):
    argv = [
        "--genesis",
        "missing",
        "--id",
        "builder1",
        "--key",
        "missing",
        "--listen",
        "127.0.0.1:7700",
        "--data",
        str(tmp_path),
        "--fault",
        "lie",
    ]
    assert main(argv) == 2
    assert "require --allow-faults" in capsys.readouterr().err


@pytest.mark.parametrize(
    "fault_args",
    [
        ["--fault", "collude"],
        ["--fault", "collude", "--hash", "A" * 64],
        ["--fault", "inject"],
        ["--fault", "lie", "--hash", "a" * 64],
    ],
)
def test_node_rejects_incomplete_or_incompatible_fault_flags(fault_args):
    args = _parser().parse_args(
        [
            "--genesis",
            "missing",
            "--id",
            "builder1",
            "--key",
            "missing",
            "--listen",
            "127.0.0.1:7700",
            "--data",
            "/tmp/data",
            "--allow-faults",
            *fault_args,
        ]
    )
    with pytest.raises(ValueError):
        _fault(args)
