"""Untrusted HTTP transport for builders and peer messages."""

import asyncio
import ipaddress
import json
import math
import re
import time
from pathlib import Path
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout, web

from .canon import _no_dup_pairs

HTTP_TIMEOUT_S = 3
_HEX64 = r"[0-9a-f]{64}"


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite JSON number")
    return parsed


def _reject_nonfinite(_: str) -> None:
    raise ValueError("nonfinite JSON constant")


async def _read_capped(stream: Any, limit: int) -> bytes | None:
    """The whole body, or None if it exceeds `limit`. `StreamReader.read(n)` returns as soon as
    *some* data arrived, so a single read can silently truncate a multi-chunk body."""
    data = bytearray()
    async for chunk in stream.iter_chunked(65536):
        data += chunk
        if len(data) > limit:
            return None
    return bytes(data)


def _error(code: str, status: int) -> web.Response:
    return web.json_response({"error": code, "detail": code.replace("_", " ")}, status=status)


def _since(request: web.Request) -> float:
    try:
        value = float(request.query.get("since", "0"))
        return value if 0 <= value < float("inf") else 0.0
    except ValueError:
        return 0.0


def _is_loopback(remote: str | None) -> bool:
    """True only for a caller on this machine (127.0.0.0/8, ::1, IPv4-mapped loopback)."""
    try:
        ip = ipaddress.ip_address(remote or "")
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def _row_envelope(row: Any) -> dict:
    return json.loads(row["envelope"])


def make_app(
    engine: Any, store: Any, g: Any, me: Any, env: Any, book: Any = None
) -> web.Application:
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
        raw = await _read_capped(request.content, 4096)
        if raw is None:
            return _error("too_large", 413)
        status, body = await engine.on_request(raw)
        return web.json_response(body, status=status)

    async def message(request: web.Request) -> web.Response:
        raw = await _read_capped(request.content, 1024)
        if raw is None:
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
        # Build logs reveal host details (paths, uid/gid, docker args, toolchain output), so they
        # stay on their own laptop (RFC rev 5 §7.9). Checked first: peers cannot even probe ids.
        if not _is_loopback(request.remote):
            return _error("not_found", 404)
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
            return web.FileResponse(path, headers={"Content-Type": "application/octet-stream"})
        except OSError:
            return _error("not_found", 404)

    async def evidence(request: web.Request) -> web.Response:
        items = []
        for row in store.list_evidence(_since(request)):
            item = dict(row)
            item["proof"] = json.loads(item["proof"]) if item["proof"] is not None else None
            items.append(item)
        return web.json_response({"now": clock(), "evidence": items})

    async def peers_route(request: web.Request) -> web.Response:
        # Signed hellos only; clients re-verify every one against genesis before using it.
        return web.json_response({"now": clock(), "hellos": book.hellos() if book else []})

    app.router.add_get("/v1/health", health)
    app.router.add_post("/v1/requests", submit)
    app.router.add_get("/v1/requests", requests)
    app.router.add_get("/v1/requests/{id}/bundle", bundle)
    app.router.add_get("/v1/requests/{id}/log", log)
    app.router.add_get("/v1/requests/{id}", get_request)
    app.router.add_post("/v1/messages", message)
    app.router.add_get("/v1/artifacts/{sha256}", artifact)
    app.router.add_get("/v1/evidence", evidence)
    app.router.add_get("/v1/peers", peers_route)
    return app


class PeerClient:
    """One session per node; pushes never block request admission."""

    def __init__(self, g: Any, me: Any, book: Any = None):
        self.g = g
        self.me = me
        self.book = book  # discovery.AddressBook: verified hello addresses (RFC rev 5 §7.15)
        self.session = ClientSession(timeout=ClientTimeout(total=HTTP_TIMEOUT_S))
        self.tasks: set[asyncio.Task] = set()

    def _url(self, node_id: str, path: str) -> str | None:
        node = self.g.node(node_id)
        if node is None or node.id == self.me.id:
            return None
        # Read on every call, so a new DHCP address is used as soon as its hello arrives.
        addr = (self.book.addr(node_id) if self.book is not None else None) or node.addr
        return f"http://{addr}{path}" if addr else None

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

    def _broadcast(self, path: str, envelope: dict, only: list[str] | None = None) -> None:
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
        return None if url is None else await self.get_json_at(url)

    async def get_json_at(self, url: str) -> Any | None:
        """GET a JSON document from an explicit URL (the CLI's local builder); None on any error."""
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    return None
                data = await _read_capped(response.content, 1024 * 1024)
                if data is None:
                    return None
                return json.loads(
                    data,
                    object_pairs_hook=_no_dup_pairs,
                    parse_float=_finite_float,
                    parse_constant=_reject_nonfinite,
                )
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
                return await _read_capped(response.content, limit)
        except (ClientError, OSError, TimeoutError, ValueError):
            return None

    async def close(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.session.close()
