import asyncio
import collections
import logging
import math
import re
import secrets
import time
from typing import TYPE_CHECKING, Any

from . import builder
from .canon import loads_strict
from .faults import Fault
from .genesis import Genesis, Node
from .model import (
    MAX_ATTEST_ENV,
    MAX_RELEASE_ENV,
    Request,
    make_envelope,
    parse_envelope,
    request_id,
)
from .select import selected
from .store import Store
from .verdict import verdict

if TYPE_CHECKING:
    from .net import PeerClient

ARTIFACT_RETENTION_S = 86400
INGEST_PER_MIN = 20
MAX_ATTEMPTS = 3  # first try + 2 retries (RFC §7.6 rule 3)

log = logging.getLogger("matrix")
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _num(x: Any) -> bool:
    return type(x) in (int, float) and math.isfinite(x)


class Engine:
    def __init__(
        self,
        g: Genesis,
        me: Node,
        sk,
        store: Store,
        peers: "PeerClient",
        env: builder.BuildEnv,
        fault: Fault,
        clock=time.time,
    ):
        self.g, self.me, self.sk, self.store = g, me, sk, store
        self.peers, self.env, self.fault, self.clock = peers, env, fault, clock
        # One request being built (held by the worker) plus at most one queued; the rest are shed.
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        self.ingest: collections.deque[float] = collections.deque()
        self.cursors: dict[str, float] = {}  # peer id -> that peer's `now` from the last pull
        self._last_expire = 0.0

    def _log(self, event: str, **kv: Any) -> None:
        log.info("%s %s %s", self.me.id, event, " ".join(f"{k}={v}" for k, v in kv.items()))

    def _peer_ids(self) -> list[str]:
        return [n.id for n in self.g.nodes if n.id != self.me.id]

    def _selected(self, rid: str) -> list[str]:
        return selected(rid, self.g.nodes, self.g.replicas)

    def _request_env(self, rid: str) -> dict | None:
        row = self.store.get_request(rid)
        env = loads_strict(row["envelope"]) if row else None
        return env if isinstance(env, dict) else None

    # --- requests ---------------------------------------------------------------------------

    def _is_forbidden(self, raw: Any) -> bool:
        """A rejected request is 403 (not 400) if its signer or repo is not allowed (RFC §7.9)."""
        obj = raw if isinstance(raw, dict) else loads_strict(raw)
        if not isinstance(obj, dict):
            return False
        signer, body = obj.get("signer"), obj.get("body")
        if isinstance(signer, str) and self.g.signer(signer) is None:
            return True
        repo = body.get("repo_url") if isinstance(body, dict) else None
        return isinstance(repo, str) and repo not in self.g.allowed_repos

    async def on_request(self, raw: bytes | dict) -> tuple[int, dict]:
        if isinstance(raw, (bytes, str)) and len(raw) > MAX_RELEASE_ENV:
            return 413, {"error": "too_large"}
        e = parse_envelope(raw, self.g)
        if e is None:
            if self._is_forbidden(raw):
                return 403, {"error": "forbidden"}
            return 400, {"error": "invalid_envelope"}
        if e.type != "release":
            return 400, {"error": "invalid_envelope", "detail": "not a release request"}
        rid = request_id(e.body)
        if self.store.get_request(rid) is not None:
            return 202, {"id": rid}  # idempotent; not forwarded again

        now = self.clock()
        while self.ingest and now - self.ingest[0] > 60:
            self.ingest.popleft()
        if len(self.ingest) >= INGEST_PER_MIN:
            return 429, {"error": "rate_limited"}
        self.fault.on_new_request()

        mine = self.me.id in self._selected(rid)
        if not self.store.add_request(rid, e.raw, now, "RECEIVED" if mine else "OBSERVING"):
            return 202, {"id": rid}
        self.ingest.append(now)
        self._log("request.new", id=rid[:8], selected=mine)
        await self.peers.broadcast_request(e.raw)
        if mine:
            self._enqueue(rid)
        return 202, {"id": rid}

    def _enqueue(self, rid: str) -> None:
        try:
            self.queue.put_nowait(rid)
        except asyncio.QueueFull:
            self.store.set_phase(rid, "SHED")
            self._log("request.shed", id=rid[:8])

    # --- build ------------------------------------------------------------------------------

    async def build_worker(self) -> None:
        while True:
            await self._build_one(await self.queue.get())

    async def _build_one(self, rid: str) -> None:
        b = self.store.get_build(rid)
        if b is not None and b["result"] is not None:
            return  # already attested
        if self.is_settled(rid):
            self.store.set_phase(rid, "MISSED")
            self.store.upsert_build(rid, error="settled")
            return

        forced = self.fault.attest_without_build()
        if forced == "STALL":
            return  # stays RECEIVED, never attests
        if forced is not None:
            await self.attest(rid, forced, None)
            return

        row = self.store.get_request(rid)
        body = self._request_env(rid)["body"]
        t0, now = row["received_at"], self.clock()
        self.store.set_phase(rid, "BUILDING")
        self.store.upsert_build(rid, started_at=now)
        self._log("build.start", id=rid[:8])
        for attempt in range(MAX_ATTEMPTS):
            outcome = await self._attempt(Request(**body), rid, attempt)
            self._log("build.outcome", id=rid[:8], kind=outcome.kind, reason=outcome.reason)
            if outcome.kind != "ERROR":
                break
            if not self.clock() + self.g.build_timeout_s < t0 + self.g.request_ttl_s:
                break  # no time left for another attempt

        if outcome.kind == "HASH":
            await self.attest(rid, outcome.result, outcome.artifact_path)
        elif outcome.kind == "FAILED":
            await self.attest(rid, "FAILED", None)
        else:  # ERROR, BAD_REF, BAD_RECIPE: abstain, never attest (invariant 6)
            self.store.set_phase(rid, "MISSED")
            self.store.upsert_build(rid, error=outcome.reason, finished_at=self.clock())

    async def _attempt(self, req: Request, rid: str, attempt: int) -> builder.Outcome:
        # asyncio.timeout, not wait_for: on 3.11 wait_for can swallow a cancel that races with
        # the build finishing (CPython gh-86296), so the worker would never stop on shutdown.
        try:
            async with asyncio.timeout(self.g.build_timeout_s):
                return await builder.build(
                    req, rid, self.g, self.env, attempt, patch=self.fault.patch
                )
        except TimeoutError:
            return builder.Outcome("ERROR", None, None, "timeout")
        except Exception:
            log.exception("%s build crashed", self.me.id)
            return builder.Outcome("ERROR", None, None, "internal error")

    async def attest(self, rid: str, result: str, artifact: str | None) -> None:
        b = self.store.get_build(rid)
        if b is not None and b["result"] is not None:
            return  # never sign two different results for one request (invariant 7)
        body = {"request_id": rid, "result": result}
        env = make_envelope("attest", self.me.id, body, self.sk, self.g)
        e = parse_envelope(env, self.g)
        assert e is not None, "own attestation must parse"
        # Persist, then broadcast: a crash in between re-sends on restart instead of re-signing.
        self.store.record_own_attestation(rid, result, artifact, e, self.clock())
        self._log("attest.sent", id=rid[:8], result=result[:8])
        if self.fault.mode == "equivocate":
            await self._equivocate(rid, env)
        else:
            await self.peers.broadcast_attest(env)
        self.detect_evidence(rid)

    async def _equivocate(self, rid: str, env: dict) -> None:
        other = make_envelope(
            "attest",
            self.me.id,
            {"request_id": rid, "result": secrets.token_hex(32)},
            self.sk,
            self.g,
        )
        ids = self._peer_ids()
        await self.peers.broadcast_attest(env, only=ids[::2])
        await self.peers.broadcast_attest(other, only=ids[1::2])

    # --- attestations -----------------------------------------------------------------------

    async def _fetch_request(self, rid: str, hint: str | None):
        """Fetch an unknown request from the pushing peer; it must hash to `rid`."""
        if hint is None or hint == self.me.id or self.g.node(hint) is None:
            return None
        d = await self.peers.get_json(hint, f"/v1/requests/{rid}")
        env = d.get("request") if isinstance(d, dict) else None
        e = parse_envelope(env, self.g)
        if e is None or e.type != "release" or request_id(e.body) != rid:
            return None
        await self.on_request(e.raw)
        return self.store.get_request(rid)

    async def on_attest(self, raw: bytes | dict, from_hint: str | None) -> tuple[int, dict]:
        if isinstance(raw, (bytes, str)) and len(raw) > MAX_ATTEST_ENV:
            return 413, {"error": "too_large"}
        e = parse_envelope(raw, self.g)
        if e is None or e.type != "attest":
            return 400, {"error": "invalid_envelope"}
        rid = e.body["request_id"]
        row = self.store.get_request(rid) or await self._fetch_request(rid, from_hint)
        if row is None:
            return 409, {"error": "unknown_request"}
        now = self.clock()
        if now - row["received_at"] > self.g.request_ttl_s:
            return 409, {"error": "expired"}
        if e.signer not in self._selected(rid):
            return 400, {"error": "invalid_envelope", "detail": "signer not selected"}
        if self.store.attestation_count(rid, e.signer) >= 2:
            return 202, {"msg_id": e.msg_id}  # two prove equivocation; more only bloat the store
        if self.store.add_attestation(e, now):
            self._log("attest.recv", signer=e.signer, id=rid[:8])
            self.detect_evidence(rid)
        return 202, {"msg_id": e.msg_id}

    # --- evidence and settlement ------------------------------------------------------------

    def detect_evidence(self, rid: str) -> None:
        row, req_env = self.store.get_request(rid), self._request_env(rid)
        if row is None or req_env is None:
            return
        now = self.clock()
        envs = self.store.attestations(rid)
        by_signer: dict[str, dict[str, dict]] = collections.defaultdict(dict)
        for env in envs:
            by_signer[env["signer"]][env["body"]["result"]] = env

        def add(kind: str, signer: str, proof: list | None) -> None:
            if self.store.add_evidence(kind, signer, rid, proof, now):
                self._log("evidence", kind=kind, signer=signer, id=rid[:8])

        for signer, results in by_signer.items():
            if len(results) >= 2:
                add("EQUIVOCATION", signer, list(results.values())[:2])

        v = verdict(req_env, envs, self.g)
        if v.state in ("AGREED", "BUILD_FAILED"):
            quorum = v.hash if v.state == "AGREED" else "FAILED"
            for signer, result in v.results.items():
                if result != quorum:
                    add("DISAGREE", signer, [by_signer[signer][result]])

        if now > row["received_at"] + 2 * self.g.build_timeout_s:
            for signer in self._selected(rid):
                if signer not in by_signer:
                    add("STALL", signer, None)

    def is_settled(self, rid: str) -> bool:
        row, req_env = self.store.get_request(rid), self._request_env(rid)
        if row is None or req_env is None:
            return True
        if self.clock() - row["received_at"] > self.g.request_ttl_s:
            return True
        return verdict(req_env, self.store.attestations(rid), self.g).state != "PENDING"

    # --- sync and recovery (A6) -------------------------------------------------------------

    async def sync_loop(self) -> None:
        while True:
            await self._sync_round()
            await asyncio.sleep(self.g.sync_interval_s)

    async def _sync_round(self) -> None:
        await asyncio.gather(*(self._sync_peer(p) for p in self._peer_ids()))
        now = self.clock()
        for row in self.store.live_requests(now, self.g.request_ttl_s):
            self.detect_evidence(row["id"])  # catches STALL, which no incoming message triggers
        if now - self._last_expire >= 3600:
            builder.expire_artifacts(self.env, now)
            self._last_expire = now

    async def _sync_peer(self, peer: str) -> None:
        try:
            await self._pull_requests(peer)
            await self._pull_bundles(peer)
        except Exception:
            log.warning("%s sync.peer_error peer=%s", self.me.id, peer, exc_info=True)

    async def _pull_requests(self, peer: str) -> None:
        since = max(
            0.0, self.cursors.get(peer, 0.0) - 60
        )  # overlap: the peer's clock is the cursor
        d = await self.peers.get_json(peer, f"/v1/requests?since={since}")
        if (
            not isinstance(d, dict)
            or not _num(d.get("now"))
            or not isinstance(d.get("requests"), list)
        ):
            return
        self.cursors[peer] = d["now"]
        for item in d["requests"]:
            if not isinstance(item, dict):
                continue
            rid, received = item.get("id"), item.get("received_at")
            if not isinstance(rid, str) or not _HEX64.fullmatch(rid) or not _num(received):
                continue
            if (
                self.store.get_request(rid) is not None
                or d["now"] - received > self.g.request_ttl_s
            ):
                continue
            detail = await self.peers.get_json(peer, f"/v1/requests/{rid}")
            if isinstance(detail, dict):
                await self.on_request(detail.get("request"))  # re-validates; honours the ingest cap

    async def _pull_bundles(self, peer: str) -> None:
        for row in self.store.live_requests(self.clock(), self.g.request_ttl_s):
            d = await self.peers.get_json(peer, f"/v1/requests/{row['id']}/bundle")
            envs = d.get("envelopes") if isinstance(d, dict) else None
            if isinstance(envs, list):
                # at most 2 attestations per signer can ever be stored
                for env in envs[: 2 * len(self.g.nodes)]:
                    await self.on_attest(env, peer)

    async def recover(self) -> None:
        for row in self.store.live_requests(self.clock(), self.g.request_ttl_s):
            rid = row["id"]
            b = self.store.get_build(rid)
            if b is not None and b["result"] is not None:
                # attested before the restart: re-send, never rebuild or re-sign
                for env in self.store.attestations(rid):
                    if env["signer"] == self.me.id:
                        await self.peers.broadcast_attest(env)
            elif row["phase"] in ("RECEIVED", "BUILDING") and self.me.id in self._selected(rid):
                self.store.set_phase(rid, "RECEIVED")
                self._enqueue(rid)
