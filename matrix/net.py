"""Untrusted HTTP transport for builders and peer messages."""

import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout, web

HTTP_TIMEOUT_S = 3
_HEX64 = r"[0-9a-f]{64}"


def _error(code: str, status: int) -> web.Response:
    return web.json_response(
        {"error": code, "detail": code.replace("_", " ")}, status=status
    )


def _since(request: web.Request) -> float:
    try:
        value = float(request.query.get("since", "0"))
        return value if 0 <= value < float("inf") else 0.0
    except ValueError:
        return 0.0


def _row_envelope(row: Any) -> dict:
    return json.loads(row["envelope"])


def make_app(engine: Any, store: Any, g: Any, me: Any, env: Any) -> web.Application:
    app = web.Application(client_max_size=4096)
    clock = getattr(engine, "clock", time.time)

    async def health(request: web.Request) -> web.Response:
        return web.json_response(
            {
                "node_id": me.id,
                "version": "0.1.0",
                "genesis_hash": g.hash,
                "now": clock(),
            }
        )

    async def submit(request: web.Request) -> web.Response:
        raw = await request.content.read(4097)
        if len(raw) > 4096:
            return _error("too_large", 413)
        status, body = await engine.on_request(raw)
        return web.json_response(body, status=status)

    async def message(request: web.Request) -> web.Response:
        raw = await request.content.read(1025)
        if len(raw) > 1024:
            return _error("too_large", 413)
        status, body = await engine.on_attest(raw, request.headers.get("X-Matrix-From"))
        return web.json_response(body, status=status)

    async def requests(request: web.Request) -> web.Response:
        return web.json_response(
            {
                "now": clock(),
                "requests": [
                    {
                        "id": row["id"],
                        "phase": row["phase"],
                        "received_at": row["received_at"],
                    }
                    for row in store.list_requests(_since(request))
                ],
            }
        )

    def lookup(request: web.Request) -> Any:
        rid = request.match_info["id"]
        if re.fullmatch(_HEX64, rid, re.ASCII) is None:
            return None
        return store.get_request(rid)

    async def get_request(request: web.Request) -> web.Response:
        row = lookup(request)
        if row is None:
            return _error("not_found", 404)
        return web.json_response(
            {
                "request": _row_envelope(row),
                "phase": row["phase"],
                "received_at": row["received_at"],
            }
        )

    async def bundle(request: web.Request) -> web.Response:
        row = lookup(request)
        if row is None:
            return _error("not_found", 404)
        return web.json_response(
            {"request": _row_envelope(row), "envelopes": store.attestations(row["id"])}
        )

    async def log(request: web.Request) -> web.Response:
        row = lookup(request)
        if row is None:
            return _error("not_found", 404)
        path = Path(env.data_dir) / "logs" / (row["id"] + ".log")
        try:
            with path.open("rb") as file:
                file.seek(0, 2)
                file.seek(max(0, file.tell() - 65536))
                data = file.read()
        except OSError:
            return _error("not_found", 404)
        return web.Response(body=data, content_type="text/plain", charset="utf-8")

    async def artifact(request: web.Request) -> web.StreamResponse:
        sha = request.match_info["sha256"]
        if re.fullmatch(_HEX64, sha, re.ASCII) is None:
            return _error("not_found", 404)
        path = store.artifact_path(sha)
        if path is None:
            return _error("not_found", 404)
        try:
            if not Path(path).is_file():
                return _error("not_found", 404)
            if getattr(engine.fault, "corrupt_artifacts", False):
                data = bytearray(await asyncio.to_thread(Path(path).read_bytes))
                if not data:
                    return _error("not_found", 404)
                data[0] ^= 0xFF
                return web.Response(body=data, content_type="application/octet-stream")
            return web.FileResponse(
                path, headers={"Content-Type": "application/octet-stream"}
            )
        except OSError:
            return _error("not_found", 404)

    async def evidence(request: web.Request) -> web.Response:
        items = []
        for row in store.list_evidence(_since(request)):
            item = dict(row)
            item["proof"] = (
                json.loads(item["proof"]) if item["proof"] is not None else None
            )
            items.append(item)
        return web.json_response({"now": clock(), "evidence": items})

    app.router.add_get("/v1/health", health)
    app.router.add_post("/v1/requests", submit)
    app.router.add_get("/v1/requests", requests)
    app.router.add_get("/v1/requests/{id}/bundle", bundle)
    app.router.add_get("/v1/requests/{id}/log", log)
    app.router.add_get("/v1/requests/{id}", get_request)
    app.router.add_post("/v1/messages", message)
    app.router.add_get("/v1/artifacts/{sha256}", artifact)
    app.router.add_get("/v1/evidence", evidence)
    return app


class PeerClient:
    """One session per node; pushes never block request admission."""

    def __init__(self, g: Any, me: Any):
        self.g = g
        self.me = me
        self.session = ClientSession(timeout=ClientTimeout(total=HTTP_TIMEOUT_S))
        self.tasks: set[asyncio.Task] = set()

    def _url(self, node_id: str, path: str) -> str | None:
        node = self.g.node(node_id)
        return (
            f"http://{node.addr}{path}"
            if node is not None and node.id != self.me.id
            else None
        )

    async def _post(self, node_id: str, path: str, envelope: dict) -> None:
        url = self._url(node_id, path)
        if url is None:
            return
        body = json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        try:
            async with self.session.post(
                url,
                data=body,
                headers={
                    "X-Matrix-From": self.me.id,
                    "Content-Type": "application/json",
                },
            ) as response:
                await response.read()
        except (ClientError, OSError, TimeoutError):
            pass

    def _broadcast(
        self, path: str, envelope: dict, only: list[str] | None = None
    ) -> None:
        for node in self.g.nodes:
            if node.id == self.me.id or (only is not None and node.id not in only):
                continue
            task = asyncio.create_task(self._post(node.id, path, envelope))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

    async def broadcast_request(self, env: dict) -> None:
        self._broadcast("/v1/requests", env)

    async def broadcast_attest(self, env: dict, only: list[str] | None = None) -> None:
        self._broadcast("/v1/messages", env, only)

    async def get_json(self, node_id: str, path: str) -> Any | None:
        url = self._url(node_id, path)
        if url is None:
            return None
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                return await response.json()
        except (ClientError, OSError, TimeoutError, ValueError):
            return None

    async def get_bytes(self, node_id: str, path: str, limit: int) -> bytes | None:
        url = self._url(node_id, path)
        if url is None:
            return None
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                data = await response.content.read(limit + 1)
                return data if len(data) <= limit else None
        except (ClientError, OSError, TimeoutError, ValueError):
            return None

    async def close(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.session.close()
