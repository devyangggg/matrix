"""In-memory fakes for the cross-track seams (AGENTS §5.2). Only Track A edits this file.

Fakes mirror the real signatures; rows are plain dicts (real Store returns sqlite3.Row, which
supports the same ``row["col"]`` access).
"""

import asyncio
import json
import secrets
from dataclasses import dataclass

from matrix.builder import Outcome
from matrix.faults import Fault
from matrix.verdict import Verdict


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class FakeStore:
    """Mirrors LLD §3.7. ``log`` (shared list) records ("store", method) calls for ordering tests."""

    def __init__(self, log: list | None = None):
        self.log = log if log is not None else []
        self.requests: dict[str, dict] = {}
        self.atts: list[
            dict
        ] = []  # {msg_id, request_id, signer, result, envelope(dict), received_at}
        self.builds: dict[str, dict] = {}
        self.evidence: list[dict] = []

    # requests
    def add_request(self, rid: str, env: dict, now: float, phase: str) -> bool:
        if rid in self.requests:
            return False
        self.requests[rid] = {
            "id": rid,
            "envelope": _dumps(env),
            "received_at": now,
            "phase": phase,
        }
        return True

    def get_request(self, rid: str):
        return self.requests.get(rid)

    def list_requests(self, since: float) -> list[dict]:
        return [r for r in self.requests.values() if r["received_at"] >= since]

    def live_requests(self, now: float, ttl: int) -> list[dict]:
        return [r for r in self.requests.values() if r["received_at"] > now - ttl]

    def set_phase(self, rid: str, phase: str) -> None:
        self.requests[rid]["phase"] = phase

    # attestations
    def add_attestation(self, e, now: float) -> bool:
        if any(a["msg_id"] == e.msg_id for a in self.atts):
            return False
        self.atts.append(
            {
                "msg_id": e.msg_id,
                "request_id": e.body["request_id"],
                "signer": e.signer,
                "result": e.body["result"],
                "envelope": e.raw,
                "received_at": now,
            }
        )
        return True

    def attestation_count(self, rid: str, signer: str) -> int:
        return sum(1 for a in self.atts if a["request_id"] == rid and a["signer"] == signer)

    def attestations(self, rid: str) -> list[dict]:
        rows = sorted(
            (a for a in self.atts if a["request_id"] == rid), key=lambda a: a["received_at"]
        )
        return [a["envelope"] for a in rows]

    # own builds
    def get_build(self, rid: str):
        return self.builds.get(rid)

    def upsert_build(self, rid: str, **fields) -> None:
        cols = dict.fromkeys(
            ("result", "artifact_path", "error", "log_path", "started_at", "finished_at")
        )  # like a real row: every column exists, NULL until set
        self.builds.setdefault(rid, {"request_id": rid, **cols}).update(fields)

    def record_own_attestation(self, rid: str, result: str, artifact_path, env, now: float) -> None:
        self.log.append(("store", "record_own_attestation"))
        self.upsert_build(rid, result=result, artifact_path=artifact_path, finished_at=now)
        self.add_attestation(env, now)
        self.set_phase(rid, "ATTESTED")

    def artifact_path(self, sha256: str) -> str | None:
        for b in self.builds.values():
            if b.get("result") == sha256:
                return b.get("artifact_path")
        return None

    # evidence
    def add_evidence(self, kind: str, signer: str, rid: str, proof, now: float) -> bool:
        if any(
            (e["kind"], e["signer"], e["request_id"]) == (kind, signer, rid) for e in self.evidence
        ):
            return False
        self.evidence.append(
            {
                "id": len(self.evidence) + 1,
                "kind": kind,
                "signer": signer,
                "request_id": rid,
                "proof": None if proof is None else _dumps(proof),
                "created_at": now,
            }
        )
        return True

    def list_evidence(self, since: float) -> list[dict]:
        return [e for e in self.evidence if e["created_at"] >= since]


class FakePeers:
    """Mirrors PeerClient (LLD §3.10). ``responses[node][path]`` feeds get_json / get_bytes."""

    def __init__(self, responses: dict | None = None, log: list | None = None):
        self.responses = responses or {}
        self.log = log if log is not None else []
        self.requests_sent: list[dict] = []
        self.attests_sent: list[tuple[dict, list[str] | None]] = []

    async def broadcast_request(self, env: dict) -> None:
        self.log.append(("peers", "broadcast_request"))
        self.requests_sent.append(env)

    async def broadcast_attest(self, env: dict, only: list[str] | None = None) -> None:
        self.log.append(("peers", "broadcast_attest"))
        self.attests_sent.append((env, only))

    async def get_json(self, node_id: str, path: str):
        return self.responses.get(node_id, {}).get(path)

    async def get_bytes(self, node_id: str, path: str, limit: int):
        return self.responses.get(node_id, {}).get(path)

    async def close(self) -> None:
        pass


class FakeEngine:
    """Records calls and returns canned (status, body); lets net/node be tested without protocol."""

    def __init__(self, fault: Fault | None = None):
        self.fault = fault or Fault()
        self.calls: list[tuple] = []
        self.request_response: tuple[int, dict] = (202, {"id": "0" * 64})
        self.attest_response: tuple[int, dict] = (202, {"msg_id": "0" * 64})

    async def on_request(self, raw):
        self.calls.append(("on_request", raw))
        return self.request_response

    async def on_attest(self, raw, from_hint=None):
        self.calls.append(("on_attest", raw, from_hint))
        return self.attest_response

    async def build_worker(self) -> None:
        self.calls.append(("build_worker",))

    async def sync_loop(self) -> None:
        self.calls.append(("sync_loop",))

    async def recover(self) -> None:
        self.calls.append(("recover",))


class FakeBuilder:
    """Stands in for ``matrix.builder.build``.

    Returns outcomes in order, repeating the last; an exception instance is raised instead.
    If ``gate`` is set the build blocks until it is set; ``started`` is set when a build begins.
    """

    def __init__(self, outcomes: list, gate: asyncio.Event | None = None):
        self.outcomes = list(outcomes)
        self.gate = gate
        self.started = asyncio.Event()
        self.calls: list[tuple] = []

    async def __call__(self, req, rid, g, env, attempt, patch=None) -> Outcome:
        self.calls.append((rid, attempt, patch))
        self.started.set()
        if self.gate is not None:
            await self.gate.wait()
        out = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(out, BaseException):
            raise out
        return out


@dataclass
class FakeFault(Fault):
    """Mirrors LLD §3.11 so Engine tests do not depend on Track C's faults.py landing."""

    new_requests: int = 0  # how many times on_new_request ran

    def on_new_request(self) -> None:
        self.new_requests += 1

    def attest_without_build(self) -> str | None:
        return {"lie": secrets.token_hex(32), "collude": self.hash, "stall": "STALL"}.get(self.mode)

    @property
    def corrupt_artifacts(self) -> bool:
        return self.mode == "bad-artifact"


def fixed_verdict(state: str, hash: str | None = None, **kw):
    """A drop-in for ``verdict()``: monkeypatch it to return a canned Verdict."""
    v = Verdict(state=state, hash=hash, **kw)
    return lambda request_env, envelopes, g: v
