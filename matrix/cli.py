"""`matrix` CLI: keygen, release, status, verify, evidence, tui (RFC §7.11, LLD §3.13)."""

import argparse
import asyncio
import hashlib
import math
import os
import random
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

from aiohttp import ClientError

from . import node
from .builder import MAX_ARTIFACT  # one limit for building and downloading (RFC §4)
from .canon import canonical_json, loads_strict
from .crypto import keygen, load_key, pubkey_hex
from .discovery import (
    BROADCAST,
    CEREMONY_TIMEOUT_S,
    DISCOVERY_PORT,
    FOUNDER_INTERVAL_S,
    ONLINE_WINDOW_S,
    AddressBook,
    Datagrams,
    Endorse,
    Founder,
    NetworkError,
    ceremony_genesis,
    check_endorsements,
    default_name,
    load_network,
    make_endorse,
    make_founder,
    params_hash,
    parse_endorse,
    parse_founder,
    seal_problem,
    short_code,
    udp_socket,
    valid_addr,
    valid_name,
)
from .genesis import Genesis, GenesisError, Node, file_genesis_hash, load_genesis, parse_genesis
from .model import make_envelope, parse_certificate, parse_envelope, request_id, valid_request
from .net import PeerClient
from .select import selected
from .verdict import Verdict, verdict

RELEASE_POLL_S = 2

EXIT_OK = 0
EXIT_MISMATCH = 1  # verify
EXIT_INVALID = 2  # verify: INVALID_CERT; release: NOT_REPRODUCIBLE
EXIT_PENDING = 3
EXIT_ERROR = 4
EXIT_BUILD_FAILED = 5

_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_DURATION = re.compile(r"([0-9]{1,9})([smhd])", re.ASCII)
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_HOSTPORT = re.compile(r"[A-Za-z0-9.-]+:[0-9]{1,5}", re.ASCII)

# Not a genesis node, so PeerClient (which skips `me`) reaches every builder.
CLIENT = Node(id="matrix-cli", operator="client", addr="localhost:0", pubkey="")


def _out(msg: str) -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(f"matrix: {msg}", file=sys.stderr, flush=True)


def _genesis_path(arg: str | None) -> str:
    # LLD L9: --genesis, then $MATRIX_GENESIS, then ~/.matrix/genesis.json
    return arg or os.environ.get("MATRIX_GENESIS") or str(Path.home() / ".matrix" / "genesis.json")


def _read_pin(arg: str | None) -> str | None:
    """The pinned genesis hash: --genesis-sha256, else ~/.matrix/genesis.sha256 (LLD §4)."""
    if arg is not None:
        text = arg
    else:
        try:
            text = (Path.home() / ".matrix" / "genesis.sha256").read_text("ascii")
        except (OSError, UnicodeDecodeError):
            return None
    pin = text.removesuffix("\n")
    return pin if _HEX64.fullmatch(pin) else None


# keygen


def cmd_keygen(a: argparse.Namespace) -> int:
    seed, pub = keygen()
    try:
        _write_key(Path(a.out), seed)
    except OSError as e:
        _err(f"cannot write key file: {e}")
        return EXIT_ERROR
    _out(pub)
    return EXIT_OK


# verify (offline: this function never opens a socket)


def cmd_verify(a: argparse.Namespace) -> int:
    try:
        data = Path(a.file).read_bytes()
        cert_raw = Path(a.cert).read_bytes()
        g = load_genesis(_genesis_path(a.genesis))
    except (OSError, GenesisError) as e:
        _err(str(e))
        return EXIT_ERROR
    pin = _read_pin(a.genesis_sha256)
    if pin is None:
        _err("no valid pinned genesis hash (--genesis-sha256 or ~/.matrix/genesis.sha256)")
        return EXIT_ERROR
    if g.hash != pin:
        _err("genesis file does not match the pinned hash")
        return EXIT_ERROR

    def invalid(why: str) -> int:
        _out(f"INVALID_CERT: {why}")
        return EXIT_INVALID

    c = parse_certificate(cert_raw, g)
    if c is None:
        return invalid("malformed certificate")
    if c.genesis_hash != pin:
        return invalid("certificate is for a different genesis")
    req = parse_envelope(c.request, g)
    if req is None or req.type != "release":
        return invalid("request is not signed by a genesis release signer")
    if req.body["repo_url"] != a.repo or req.body["tag"] != a.tag:
        return invalid(f"certificate is for {req.body['repo_url']}@{req.body['tag']}")
    if a.commit is not None and req.body["commit"] != a.commit:
        return invalid(f"certificate is for commit {req.body['commit']}")
    # Invariant 4: the request comes from the caller-checked certificate, not from attestations.
    v = verdict(c.request, c.attestations, g)
    if v.state != "AGREED":
        return invalid(f"attestations give {v.state}, not AGREED")
    if hashlib.sha256(data).hexdigest() != v.hash:
        _out(f"MISMATCH: file sha256 differs from the certified {v.hash}")
        return EXIT_MISMATCH
    _out(f"REPRODUCED {v.hash} {a.repo}@{a.tag}")
    return EXIT_OK


# network helpers (every response is untrusted; only signed envelopes are believed)


async def _submit(peers: PeerClient, node: Node, env: dict) -> bool:
    url = peers._url(node.id, "/v1/requests")  # address book first, then genesis addr
    if url is None:
        return False  # no verified address for this builder: try the next operator
    headers = {"Content-Type": "application/json"}
    try:
        async with peers.session.post(url, data=canonical_json(env), headers=headers) as r:
            await r.read()
            return r.status == 202
    except (ClientError, OSError, TimeoutError):
        return False


class ClientBook(AddressBook):
    """The client's view of where builders are (LLD §3.13): verified hellos from the local
    builder's /v1/peers. The local builder itself is reached at --node (loopback by default), so
    its loopback-only routes (the build log) work."""

    def __init__(self, g: Genesis, local: str):
        super().__init__(g)
        self.local = local
        self.local_id: str | None = None  # genesis id the local builder reported
        self.peers_now: float | None = None  # the local builder's clock, from /v1/peers

    def addr(self, node_id: str) -> str | None:
        return self.local if node_id == self.local_id else super().addr(node_id)

    def online(self, node_id: str, now: float | None = None) -> bool:
        # A client has no receive times: judge by the hello's own timestamp (L41).
        seq = self.seqs.get(node_id)
        return (
            seq is not None
            and self.peers_now is not None
            and self.peers_now - seq / 1000 < ONLINE_WINDOW_S
        )


async def refresh(peers: PeerClient, book: ClientBook) -> None:
    """Ask the local builder who it is and, without static addresses, where the others are.
    Untrusted: every hello is re-verified against genesis; the worst a lying local builder can
    do is hide addresses (liveness), never forge them."""
    g = book.g
    h = await peers.get_json_at(f"http://{book.local}/v1/health")
    nid = h.get("node_id") if isinstance(h, dict) else None
    ok = isinstance(nid, str) and g.node(nid) is not None and h.get("genesis_hash") == g.hash
    book.local_id = nid if ok else None
    if all(n.addr for n in g.nodes):
        return  # dev genesis: static addresses
    d = await peers.get_json_at(f"http://{book.local}/v1/peers")
    if not isinstance(d, dict):
        return
    now = d.get("now")
    if type(now) in (int, float) and math.isfinite(now):
        book.peers_now = float(now)
    hellos = d.get("hellos")
    if isinstance(hellos, list):
        for raw in hellos[: 4 * len(g.nodes)]:
            book.accept(raw)


async def open_client(g: Genesis, local: str) -> tuple[PeerClient, ClientBook]:
    book = ClientBook(g, local)
    peers = PeerClient(g, CLIENT, book)
    await refresh(peers, book)
    return peers, book


def _online(g: Genesis, book: ClientBook) -> set[str]:
    return {n.id for n in g.nodes if book.online(n.id)}


def _submit_targets(g: Genesis, online: frozenset[str] | set[str] = frozenset()) -> list[Node]:
    """First node of every operator, online ones first, otherwise in genesis order."""
    first: dict[str, Node] = {}
    for n in sorted(g.nodes, key=lambda n: n.id not in online):  # stable sort
        first.setdefault(n.operator, n)
    return list(first.values())


async def _submit_quorum(
    peers: PeerClient, g: Genesis, env: dict, online: frozenset[str] | set[str] = frozenset()
) -> int:
    """Submit until f+1 distinct operators accepted: at most f are faulty, so one accepting
    operator is honest and forwards the request. A single acceptance proves nothing (it may be
    a faulty builder that drops it). Returns the number of operators that accepted."""
    accepted = 0
    for n in _submit_targets(g, online):
        if accepted > g.f:
            break
        accepted += await _submit(peers, n, env)
    return accepted


async def collect(peers: PeerClient, g: Genesis, rid: str) -> tuple[dict[str, dict], set[str]]:
    """Union of every builder's /bundle by msg_id, and the set of builders that answered."""
    path = f"/v1/requests/{rid}/bundle"
    replies = await asyncio.gather(*(peers.get_json(n.id, path) for n in g.nodes))
    union: dict[str, dict] = {}
    answered: set[str] = set()
    for n, b in zip(g.nodes, replies):
        if not isinstance(b, dict) or not isinstance(b.get("envelopes"), list):
            continue
        answered.add(n.id)
        for raw in b["envelopes"]:
            e = parse_envelope(raw, g)
            if e is not None and e.type == "attest" and e.body["request_id"] == rid:
                union[e.msg_id] = e.raw
    return union, answered


async def fetch_request(peers: PeerClient, g: Genesis, rid: str) -> dict | None:
    """A signed release envelope from any builder, accepted only if it hashes to `rid`."""
    replies = await asyncio.gather(*(peers.get_json(n.id, f"/v1/requests/{rid}") for n in g.nodes))
    for d in replies:
        e = parse_envelope(d.get("request"), g) if isinstance(d, dict) else None
        if e is not None and e.type == "release" and request_id(e.body) == rid:
            return e.raw
    return None


async def _download(peers: PeerClient, v: Verdict) -> bytes | None:
    signers = [s for s, r in v.results.items() if r == v.hash]
    random.shuffle(signers)  # do not always load the same builder
    for s in signers:
        data = await peers.get_bytes(s, f"/v1/artifacts/{v.hash}", MAX_ARTIFACT)
        if data is not None and hashlib.sha256(data).hexdigest() == v.hash:
            return data
    return None


def quorum_result(v: Verdict) -> str | None:
    return v.hash if v.state == "AGREED" else "FAILED" if v.state == "BUILD_FAILED" else None


def builder_rows(g: Genesis, rid: str, v: Verdict) -> list[tuple[str, str, str, str]]:
    """(builder, operator, result, mark) for each selected builder; mark is ok/DISAGREE/..."""
    q = quorum_result(v)
    rows = []
    for nid in selected(rid, g.nodes, g.replicas):
        res = v.results.get(nid, "-")
        if nid in v.equivocators:
            res, mark = "-", "EQUIVOCATION"
        elif res == "-" or q is None:
            mark = ""
        else:
            mark = "ok" if res == q else "DISAGREE"
        rows.append((nid, g.node(nid).operator, res, mark))
    return rows


def _print_table(g: Genesis, rid: str, v: Verdict) -> None:
    _out(f"request {rid}")
    _out(f"verdict {v.state}" + (f" {v.hash}" if v.hash else ""))
    for nid, op, res, mark in builder_rows(g, rid, v):
        _out(f"  {nid:<12} {op:<10} {res[:16]:<16} {mark}")


def check_proof(item: dict, g: Genesis) -> bool:
    """Only EQUIVOCATION is self-contained: two signed, conflicting attestations
    by the named signer for the named request. DISAGREE needs a verified request
    and quorum; STALL and unknown kinds cannot be proved by this payload alone.
    """
    if item.get("kind") != "EQUIVOCATION":
        return False
    proof = item.get("proof")
    if not isinstance(proof, list):
        return False
    envs = [parse_envelope(p, g) for p in proof]
    if not envs or any(
        e is None
        or e.type != "attest"
        or e.signer != item.get("signer")
        or e.body["request_id"] != item.get("request_id")
        for e in envs
    ):
        return False
    return len({e.body["result"] for e in envs}) >= 2


def _load(a: argparse.Namespace) -> Genesis | None:
    try:
        return load_genesis(_genesis_path(a.genesis))
    except GenesisError as e:
        _err(str(e))
        return None


# release


def _local(a: argparse.Namespace) -> str | None:
    """--node, else $MATRIX_NODE, else 127.0.0.1:7700 (the laptop's own builder)."""
    local = a.node or os.environ.get("MATRIX_NODE") or "127.0.0.1:7700"
    if not _HOSTPORT.fullmatch(local):
        _err(f"--node must be HOST:PORT, got {local!r}")
        return None
    return local


def cmd_release(a: argparse.Namespace) -> int:
    g = _load(a)
    local = _local(a)
    if g is None or local is None:
        return EXIT_ERROR
    key = a.key or str(Path.home() / ".matrix" / "keys" / "release.key")
    try:
        sk = load_key(key)
    except (OSError, ValueError) as e:
        _err(f"cannot load key: {e}")
        return EXIT_ERROR
    return asyncio.run(_release(a, g, sk, local))


async def _release(a: argparse.Namespace, g: Genesis, sk: Any, local: str) -> int:
    pub = pubkey_hex(sk)
    signer = next((s for s in g.release_signers if s.pubkey == pub), None)
    if signer is None:
        _err("key is not a genesis release signer")
        return EXIT_ERROR
    body = {"v": 1, "repo_url": a.repo, "commit": a.commit, "tag": a.tag}
    if not valid_request(body, g):
        _err("invalid request: repo not allowed, or bad commit/tag format")
        return EXIT_ERROR
    name = a.output if a.output is not None else a.repo.rsplit("/", 1)[-1]
    if not _NAME.fullmatch(name) or name in (".", ".."):
        _err(f"invalid output name {name!r}")
        return EXIT_ERROR

    env = make_envelope("release", signer.id, body, sk, g)
    rid = request_id(body)
    _out(f"request {rid} {a.repo}@{a.tag}")
    peers, book = await open_client(g, local)
    try:
        accepted = await _submit_quorum(peers, g, env, _online(g, book))
        if accepted <= g.f:
            _err(f"only {accepted} operators accepted the request; need {g.f + 1}")
            if not all(n.addr for n in g.nodes) and not book.seqs:
                _err(f"no builder addresses: is `matrix up` running at {local}? (--node)")
            return EXIT_ERROR
        deadline = time.monotonic() + a.wait
        ever: set[str] = set()
        got: tuple[str, bytes] | None = None  # (hash, artifact bytes)
        while True:
            await refresh(peers, book)  # a laptop may have rejoined with a new address
            union, answered = await collect(peers, g, rid)
            ever |= answered
            v = verdict(env, union.values(), g)  # our own signed request, never a peer's
            if v.state == "AGREED" and (got is None or got[0] != v.hash):
                data = await _download(peers, v)
                got = (v.hash, data) if data is not None else None
            settled = v.state != "PENDING" and (v.state != "AGREED" or got is not None)
            if (settled and len(ever) > g.f) or time.monotonic() >= deadline:
                break
            await asyncio.sleep(RELEASE_POLL_S)
    finally:
        await peers.close()

    _print_table(g, rid, v)
    if len(ever) <= g.f:
        _err(f"only {len(ever)} builders answered; need at least {g.f + 1}")
        return EXIT_ERROR
    if v.state == "AGREED" and got is not None:
        cert = {
            "v": 1,
            "genesis_hash": g.hash,
            "request": env,
            "attestations": sorted(
                (
                    e
                    for e in union.values()
                    if e["body"]["result"] == v.hash and v.results.get(e["signer"]) == v.hash
                ),
                key=lambda e: e["signer"],
            ),
        }
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(got[1])
        (out / name).chmod(0o755)
        (out / f"{name}.matrix.json").write_bytes(canonical_json(cert))
        if any(m == "DISAGREE" for *_, m in builder_rows(g, rid, v)):
            _out("WARNING: some builders disagree with the certified hash (reproducibility)")
        _out(f"CERTIFIED {v.hash} -> {out / name}")
        return EXIT_OK
    if v.state == "AGREED":
        _out("PENDING: no builder served an artifact matching the certified hash")
        return EXIT_PENDING
    _out(v.state)
    codes = {"BUILD_FAILED": EXIT_BUILD_FAILED, "NOT_REPRODUCIBLE": EXIT_INVALID}
    return codes.get(v.state, EXIT_PENDING if v.state == "PENDING" else EXIT_ERROR)


# status


def cmd_status(a: argparse.Namespace) -> int:
    if not _HEX64.fullmatch(a.id):
        _err("ID must be 64 lowercase hex")
        return EXIT_ERROR
    g = _load(a)
    local = _local(a)
    return EXIT_ERROR if g is None or local is None else asyncio.run(_status(a.id, g, local))


async def _status(rid: str, g: Genesis, local: str) -> int:
    peers, _ = await open_client(g, local)
    try:
        env = await fetch_request(peers, g, rid)
        if env is None:
            _err("no builder returned a valid request with this ID")
            return EXIT_ERROR
        union, _ = await collect(peers, g, rid)
    finally:
        await peers.close()
    v = verdict(env, union.values(), g)
    b = env["body"]
    _out(f"{b['repo_url']}@{b['tag']} commit {b['commit']} signer {env['signer']}")
    _print_table(g, rid, v)
    if v.state == "INVALID":
        return EXIT_ERROR
    return EXIT_PENDING if v.state == "PENDING" else EXIT_OK


# evidence


def cmd_evidence(a: argparse.Namespace) -> int:
    m = _DURATION.fullmatch(a.since)
    if m is None:
        _err("--since must look like 30s, 10m, 1h or 2d")
        return EXIT_ERROR
    g = _load(a)
    local = _local(a)
    if g is None or local is None:
        return EXIT_ERROR
    # Builders filter on their own clock; skew between laptops only widens or narrows the window.
    since = max(0, int(time.time()) - int(m[1]) * _UNITS[m[2]])
    return asyncio.run(_evidence(since, g, local))


async def gather_evidence(peers: PeerClient, g: Genesis, since: int) -> list[dict] | None:
    """Evidence from every builder, deduplicated by (kind, signer, request_id); None if no
    builder answered."""
    replies = await asyncio.gather(
        *(peers.get_json(n.id, f"/v1/evidence?since={since}") for n in g.nodes)
    )
    seen: dict[tuple, dict] = {}
    answered = False
    for r in replies:
        if not isinstance(r, dict) or not isinstance(r.get("evidence"), list):
            continue
        answered = True
        for item in r["evidence"]:
            if isinstance(item, dict) and all(
                isinstance(item.get(k), str) for k in ("kind", "signer", "request_id")
            ):
                seen.setdefault((item["kind"], item["signer"], item["request_id"]), item)
    return list(seen.values()) if answered else None


async def _evidence(since: int, g: Genesis, local: str) -> int:
    peers, _ = await open_client(g, local)
    try:
        items = await gather_evidence(peers, g, since)
    finally:
        await peers.close()
    if items is None:
        _err("no builder answered")
        return EXIT_ERROR
    for it in items:
        proof = "proof-ok" if check_proof(it, g) else "unverified"
        _out(f"{it['kind']:<12} {it['signer']:<12} {it['request_id'][:16]} {proof}")
    if not items:
        _out("no evidence")
    return EXIT_OK


# tui


def cmd_tui(a: argparse.Namespace) -> int:
    g = _load(a)
    local = _local(a)
    if g is None or local is None:
        return EXIT_ERROR
    from .tui import run_tui  # lazy: Textual is only needed for this command

    return run_tui(g, local)


# up: founding ceremony, then the node (RFC rev 5 §7.16, LLD §3.13)


class UdpBus:
    """Ceremony transport: broadcast on UDP DISCOVERY_PORT. Tests swap in an in-memory bus."""

    def __init__(self, port: int = DISCOVERY_PORT):
        self.port = port
        self.transport: asyncio.DatagramTransport | None = None

    async def open(self, on_datagram) -> None:
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: Datagrams(on_datagram), sock=udp_socket(self.port)
        )

    def send(self, data: bytes) -> None:
        try:
            self.transport.sendto(data, (BROADCAST, self.port))
        except OSError:
            pass  # no network right now: the next round retries

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


def _stdin_lines() -> "asyncio.Queue[str]":
    """Lines typed by the user, read on a daemon thread so the event loop keeps listening and
    an interrupted ceremony never waits for Enter on exit. EOF arrives as ""."""
    loop = asyncio.get_running_loop()
    q: asyncio.Queue[str] = asyncio.Queue()

    def put(line: str) -> None:
        try:
            loop.call_soon_threadsafe(q.put_nowait, line)
        except RuntimeError:
            pass  # the loop already closed

    def reader() -> None:
        try:
            for line in sys.stdin:
                put(line)
        except (OSError, ValueError):
            pass  # stdin closed or not readable: treated as end of input
        put("")

    threading.Thread(target=reader, daemon=True).start()
    return q


async def ceremony(
    params: dict,
    name: str,
    sk: Any,
    release_sk: Any,
    bus: Any,
    ask,
    timeout: float = CEREMONY_TIMEOUT_S,
    interval: float = FOUNDER_INTERVAL_S,
) -> tuple[dict, list[dict], bytes] | None:
    """Found the network with the other laptops. Returns (genesis, endorsements, own endorse)
    or None if aborted; nothing is written here. `ask(kind)` returns the next typed line for the
    question `kind` ("seal": Enter, "confirm": y/N)."""
    loop = asyncio.get_running_loop()
    nid, me_pub = params["name"], pubkey_hex(sk)
    own = make_founder(params, name, sk, release_sk)
    founders: dict[str, Founder] = {me_pub: parse_founder(own, nid)}
    endorses: dict[str, Endorse] = {}
    mine = params_hash(params)
    sealed: dict[str, str] = {}  # after the seal: genesis id -> pubkey, the only keys that count

    def show(f: Founder) -> None:
        flag = "" if f.params_hash == mine else "  params MISMATCH (different network.toml)"
        _out(f"  + {f.id:<24} {f.pubkey[:8]}{flag}")

    def on_datagram(data: bytes, src) -> None:
        f = parse_founder(data, nid)
        if f is not None:
            prev = founders.get(f.pubkey)
            founders[f.pubkey] = f  # latest wins
            if prev is None or (prev.id, prev.params_hash) != (f.id, f.params_hash):
                show(f)
            return
        # Before the seal, founders' keys; after it, only the sealed genesis keys, so a late
        # rogue using a member's name cannot shadow that member's endorsement.
        e = parse_endorse(data, sealed or {x.id: x.pubkey for x in founders.values()})
        if e is not None:
            endorses[e.signer] = e

    await bus.open(on_datagram)
    sending = [own]

    async def announce() -> None:
        while True:
            for msg in sending:
                bus.send(msg)
            await asyncio.sleep(interval)

    announcer = asyncio.create_task(announce())
    try:
        _out(f"Founding network {nid!r} as {name} ({me_pub[:8]}). Founders found:")
        show(founders[me_pub])
        _out("Press Enter to seal when every laptop is listed.")
        while True:
            line = await ask("seal")
            if not line:
                _err("stdin closed: the ceremony needs a terminal")
                return None
            problem = seal_problem(params, list(founders.values()), me_pub)
            if problem is None:
                break
            _out(f"cannot seal yet: {problem}")
        fs = list(founders.values())  # frozen: later founders do not change our genesis
        raw = ceremony_genesis(params, fs)
        g = parse_genesis(raw)
        _out(f"Sealed {len(fs)} founders:")
        for n in g.nodes:
            _out(f"  {n.id:<24} {n.pubkey[:8]}")
        _out(f"Short code: {short_code(g.hash)}")
        _out("Read it aloud. Do all screens show this code and this list? [y/N]")
        if (await ask("confirm")).strip().lower() != "y":
            _err("aborted: nothing written")
            return None

        sealed.update({n.id: n.pubkey for n in g.nodes})
        endorses = {k: e for k, e in endorses.items() if parse_endorse(e.raw, sealed)}
        me = next(n for n in g.nodes if n.pubkey == me_pub)
        endorse = make_endorse(g, me, sk)
        endorses[me.id] = parse_endorse(endorse, {me.id: me_pub})
        sending.append(endorse)
        bus.send(endorse)
        ids = {n.id for n in g.nodes}
        deadline = loop.time() + timeout
        seen = 0
        while True:
            conflict = sorted(
                e.signer for e in endorses.values() if e.signer in ids and e.genesis_hash != g.hash
            )
            if conflict:
                _err(f"{', '.join(conflict)} sealed a different genesis: compare the lists, rerun")
                return None
            ok = [e.raw for e in endorses.values() if e.signer in ids and e.genesis_hash == g.hash]
            if check_endorsements(g, ok):
                break
            if len(ok) != seen:
                seen = len(ok)
                _out(f"waiting for every laptop to confirm: {seen}/{len(ids)}")
            if loop.time() > deadline:
                _err("not every laptop confirmed in time: nothing written")
                return None
            await asyncio.sleep(0.2)
        _out(f"Network founded: {len(ids)} builders, genesis {g.hash}")
        return raw, sorted(ok, key=lambda e: e["signer"]), endorse
    finally:
        announcer.cancel()
        await asyncio.gather(announcer, return_exceptions=True)
        bus.close()


def _write_key(path: Path, seed: str) -> None:
    # O_EXCL: never overwrite an existing key; 0600: the seed is a secret (LLD §4).
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(seed + "\n")


def _ensure_key(path: Path) -> Any:
    """Load the key, generating it locally on first use. Private keys never leave the laptop."""
    if not path.exists():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_key(path, keygen()[0])
    return load_key(str(path))


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _archive(home: Path) -> Path:
    """--refound: keep the old network next to the new one; nothing is deleted."""
    try:
        code = short_code(file_genesis_hash(str(home / "genesis.json")))
    except GenesisError:
        code = "unknown"
    dest, i = home / f"old-{code}", 2
    while dest.exists():
        dest, i = home / f"old-{code}-{i}", i + 1
    dest.mkdir(mode=0o700)
    for name in ("genesis.json", "genesis.sha256", "endorsements.json", "data"):
        if (home / name).exists():
            os.replace(home / name, dest / name)
    return dest


def _check_founded(home: Path) -> Genesis | None:
    """An existing network: the pin and every founder's endorsement must still match."""
    try:
        g = load_genesis(str(home / "genesis.json"))
        pin = (home / "genesis.sha256").read_text("ascii").removesuffix("\n")
        ends = loads_strict((home / "endorsements.json").read_bytes())
    except (OSError, UnicodeDecodeError, GenesisError) as e:
        _err(f"cannot load the founded network in {home}: {e}")
        return None
    if pin != g.hash or not isinstance(ends, list) or not check_endorsements(g, ends):
        _err(f"{home}: genesis does not match its pin or endorsements; refusing to start")
        return None
    return g


async def _keep_endorsing(data: bytes, seconds: float) -> None:
    """Laptops that confirmed later can still finish their ceremony (L42). Send only: the node
    owns the discovery port now."""
    loop = asyncio.get_running_loop()
    with udp_socket(None) as sock:
        end = loop.time() + seconds
        while loop.time() < end:
            try:
                sock.sendto(data, (BROADCAST, DISCOVERY_PORT))
            except OSError:
                pass
            await asyncio.sleep(FOUNDER_INTERVAL_S)


def cmd_up(a: argparse.Namespace) -> int:
    home = Path(a.home).expanduser() if a.home else Path.home() / ".matrix"
    try:
        node._fault(a)  # fault flags are validated before anything else (inert without opt-in)
    except ValueError as e:
        _err(str(e))
        return EXIT_ERROR
    if a.advertise is not None and not valid_addr(a.advertise):
        _err("--advertise must be <IPv4>:<port>")
        return EXIT_ERROR
    if a.name is not None and not valid_name(a.name):
        _err("--name must match [A-Za-z0-9_-]{1,24}")
        return EXIT_ERROR
    return asyncio.run(_up(a, home, node))


async def _up(a: argparse.Namespace, home: Path, node: Any) -> int:
    keys = home / "keys"
    endorse: bytes | None = None
    if (home / "genesis.json").exists() and not a.refound:
        if _check_founded(home) is None:
            return EXIT_ERROR
    else:
        try:
            params = load_network("network.toml")
        except NetworkError as e:
            _err(f"{e} (run `matrix up` from the repo checkout)")
            return EXIT_ERROR
        name = a.name or default_name()
        if not valid_name(name):
            _err(f"hostname gives an invalid name {name!r}: pass --name")
            return EXIT_ERROR
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            sk, release_sk = _ensure_key(keys / "node.key"), _ensure_key(keys / "release.key")
        except (OSError, ValueError) as e:
            _err(f"cannot create or load keys in {keys}: {e}")
            return EXIT_ERROR
        try:
            lines = _stdin_lines()
            result = await ceremony(params, name, sk, release_sk, UdpBus(), lambda _: lines.get())
        except OSError as e:
            _err(f"cannot use UDP port {DISCOVERY_PORT}: {e} (is `matrix up` already running?)")
            return EXIT_ERROR
        if result is None:
            return EXIT_ERROR
        raw, endorsements, endorse = result
        if a.refound and (home / "genesis.json").exists():
            _out(f"previous network moved to {_archive(home)}")
        g = parse_genesis(raw)
        _write_atomic(home / "genesis.json", canonical_json(raw))
        _write_atomic(home / "genesis.sha256", (g.hash + "\n").encode("ascii"))
        _write_atomic(home / "endorsements.json", canonical_json(endorsements))
        _out(f"pin for consumers: {g.hash} (also in {home / 'genesis.sha256'})")

    g = load_genesis(str(home / "genesis.json"))
    try:
        pub = pubkey_hex(load_key(str(keys / "node.key")))
    except (OSError, ValueError) as e:
        _err(f"cannot load {keys / 'node.key'}: {e}")
        return EXIT_ERROR
    me = next((n for n in g.nodes if n.pubkey == pub), None)
    if me is None:
        _err("this laptop's node key is not in the founded genesis")
        return EXIT_ERROR
    args = argparse.Namespace(
        genesis=str(home / "genesis.json"),
        id=me.id,
        key=str(keys / "node.key"),
        listen="0.0.0.0:7700",
        data=str(home / "data"),
        advertise=a.advertise,
        no_discovery=False,
        allow_faults=a.allow_faults,
        fault=a.fault,
        patch=a.patch,
        hash=a.hash,
    )
    extra = asyncio.create_task(_keep_endorsing(endorse, CEREMONY_TIMEOUT_S)) if endorse else None
    _out(f"{me.id}: builder starting on 0.0.0.0:7700 (Ctrl-C to stop)")
    try:
        await node.run(args)
    except ValueError as e:
        _err(str(e))
        return EXIT_ERROR
    except Exception as e:  # noqa: BLE001  e.g. Docker missing: report, never a traceback
        _err(f"builder stopped: {e!r}")
        return EXIT_ERROR
    finally:
        if extra is not None:
            extra.cancel()
            await asyncio.gather(extra, return_exceptions=True)
    return EXIT_OK


# entry point


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="matrix", description="Matrix release gate")
    p.add_argument("--genesis", help="genesis.json (default $MATRIX_GENESIS or ~/.matrix/)")
    p.add_argument("--node", help="local builder HOST:PORT (default $MATRIX_NODE, 127.0.0.1:7700)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="generate an Ed25519 key; prints the public key")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("verify", help="check a binary against its certificate, offline")
    s.add_argument("file")
    s.add_argument("--cert", required=True)
    s.add_argument("--repo", required=True)
    s.add_argument("--tag", required=True)
    s.add_argument("--commit")
    s.add_argument("--genesis-sha256", help="pinned genesis hash (default ~/.matrix/)")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("release", help="sign, submit, wait for a quorum, write the certificate")
    s.add_argument("--repo", required=True)
    s.add_argument("--tag", required=True)
    s.add_argument("--commit", required=True)
    s.add_argument("--key", help="release-signer key (default ~/.matrix/keys/release.key)")
    s.add_argument("--wait", type=int, default=600, help="seconds (default 600)")
    s.add_argument("--out", default="dist")
    s.add_argument("--output", help="artifact file name (default: repo name)")
    s.set_defaults(fn=cmd_release)

    s = sub.add_parser("status", help="per-builder results and verdict for a request ID")
    s.add_argument("id")
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("evidence", help="evidence collected by all builders")
    s.add_argument("--since", default="1h")
    s.set_defaults(fn=cmd_evidence)

    s = sub.add_parser("tui", help="live view of builders, releases and evidence")
    s.set_defaults(fn=cmd_tui)

    s = sub.add_parser("up", help="found the network if needed (ceremony), then run the builder")
    s.add_argument("--name", help="this laptop's name (default: hostname)")
    s.add_argument("--home", help="state directory (default ~/.matrix)")
    s.add_argument("--refound", action="store_true", help="found a new network")
    s.add_argument("--advertise", help="address put in hellos, <IPv4>:<port>")
    s.add_argument("--allow-faults", action="store_true")
    s.add_argument("--fault", choices=node._MODES)
    s.add_argument("--patch")
    s.add_argument("--hash")
    s.set_defaults(fn=cmd_up)
    return p


def run(argv: list[str] | None = None) -> int:
    p = _parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:  # argparse exits 2 on bad usage; 2 means INVALID here, so remap
        return EXIT_OK if e.code == 0 else EXIT_ERROR
    try:
        return a.fn(a)
    except Exception as e:  # noqa: BLE001  fail closed: an unexpected error is never success
        _err(f"unexpected error: {e!r}")
        return EXIT_ERROR


def main() -> None:
    sys.exit(run())
