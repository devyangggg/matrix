"""`matrix` CLI: up, release, status, evidence, tui, verify, keygen, help (RFC §7.11, LLD §3.13)."""

import argparse
import asyncio
import hashlib
import logging
import math
import os
import random
import re
import select
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

from aiohttp import ClientError

from . import node
from .builder import MAX_ARTIFACT, isolation  # one artifact limit for building and downloading
from .canon import canonical_json, loads_strict
from .crypto import keygen, load_key, pubkey_hex
from .discovery import (
    CEREMONY_TIMEOUT_S,
    DISCOVERY_PORT,
    FOUNDER_INTERVAL_S,
    ONLINE_WINDOW_S,
    AddressBook,
    Datagrams,
    Endorse,
    Founder,
    NetworkError,
    Seal,
    broadcast_targets,
    ceremony_genesis,
    check_endorsements,
    default_name,
    load_network,
    local_ip,
    make_endorse,
    make_founder,
    make_seal,
    params_hash,
    parse_endorse,
    parse_founder,
    parse_seal,
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

log = logging.getLogger(__name__)

RELEASE_POLL_S = 2
_CHECKOUT = (
    Path(__file__).resolve().parent.parent
)  # the repo this package runs from (uv sync is editable)

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
    log.info(
        "verify: read %s (%d bytes), certificate %s, genesis %s", a.file, len(data), a.cert, g.hash
    )
    pin = _read_pin(a.genesis_sha256)
    if pin is None:
        _err("no valid pinned genesis hash (--genesis-sha256 or ~/.matrix/genesis.sha256)")
        return EXIT_ERROR
    if g.hash != pin:
        _err("genesis file does not match the pinned hash")
        return EXIT_ERROR
    log.info("verify: genesis matches the pin %s", pin)

    def invalid(why: str) -> int:
        log.info("verify: failed: %s", why)
        _out(f"INVALID_CERT: {why}")
        return EXIT_INVALID

    c = parse_certificate(cert_raw, g)
    if c is None:
        return invalid("malformed certificate")
    if c.genesis_hash != pin:
        return invalid("certificate is for a different genesis")
    log.info("verify: certificate parsed, %d attestations, same genesis", len(c.attestations))
    req = parse_envelope(c.request, g)
    if req is None or req.type != "release":
        return invalid("request is not signed by a genesis release signer")
    if req.body["repo_url"] != a.repo or req.body["tag"] != a.tag:
        return invalid(f"certificate is for {req.body['repo_url']}@{req.body['tag']}")
    if a.commit is not None and req.body["commit"] != a.commit:
        return invalid(f"certificate is for commit {req.body['commit']}")
    log.info("verify: request signature and expected repo/tag/commit checked")
    # Invariant 4: the request comes from the caller-checked certificate, not from attestations.
    v = verdict(c.request, c.attestations, g)
    if v.state != "AGREED":
        return invalid(f"attestations give {v.state}, not AGREED")
    log.info("verify: verdict AGREED on %s with %d results", v.hash, len(v.results))
    if hashlib.sha256(data).hexdigest() != v.hash:
        _out(f"MISMATCH: file sha256 differs from the certified {v.hash}")
        return EXIT_MISMATCH
    _out(f"REPRODUCED {v.hash} {a.repo}@{a.tag}")
    return EXIT_OK


# network helpers (every response is untrusted; only signed envelopes are believed)


async def _submit(peers: PeerClient, node: Node, env: dict) -> bool:
    url = peers._url(node.id, "/v1/requests")  # address book first, then genesis addr
    if url is None:
        log.info("submit: %s has no verified address, skipped", node.id)
        return False  # no verified address for this builder: try the next operator
    headers = {"Content-Type": "application/json"}
    try:
        async with peers.session.post(url, data=canonical_json(env), headers=headers) as r:
            await r.read()
            log.info(
                "submit: POST %s -> %d (%s)",
                url,
                r.status,
                "accepted" if r.status == 202 else "refused",
            )
            return r.status == 202
    except (ClientError, OSError, TimeoutError) as e:
        log.info("submit: POST %s failed: %s: %s", url, type(e).__name__, e)
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
    log.info("refresh: local builder %s health: %s", book.local, h)
    nid = h.get("node_id") if isinstance(h, dict) else None
    ok = isinstance(nid, str) and g.node(nid) is not None and h.get("genesis_hash") == g.hash
    book.local_id = nid if ok else None
    log.info(
        "refresh: local builder is %s (%s)",
        nid if ok else None,
        "genesis matches" if ok else "unreachable or other genesis",
    )
    if all(n.addr for n in g.nodes):
        log.debug("refresh: genesis has static addresses, /v1/peers not needed")
        return  # dev genesis: static addresses
    d = await peers.get_json_at(f"http://{book.local}/v1/peers")
    if not isinstance(d, dict):
        log.info("refresh: /v1/peers from %s gave nothing", book.local)
        return
    now = d.get("now")
    if type(now) in (int, float) and math.isfinite(now):
        book.peers_now = float(now)
    hellos = d.get("hellos")
    if isinstance(hellos, list):
        log.debug("refresh: %d hellos from the local builder, re-verifying each", len(hellos))
        for raw in hellos[: 4 * len(g.nodes)]:
            book.accept(raw)
        log.info("refresh: verified addresses: %s", {n.id: book.addr(n.id) for n in g.nodes})


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
        log.info(
            "submit: trying %s (operator %s), %d of %d accepted so far",
            n.id,
            n.operator,
            accepted,
            g.f + 1,
        )
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
        log.debug("collect: %s answered with %d envelopes", n.id, len(b["envelopes"]))
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
        ok = data is not None and hashlib.sha256(data).hexdigest() == v.hash
        log.info(
            "download: artifact from %s: %s",
            s,
            "ok, hash matches" if ok else "missing or hash mismatch",
        )
        if ok:
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
    path = _genesis_path(a.genesis)
    try:
        g = load_genesis(path)
    except GenesisError as e:
        _err(str(e))
        return None
    log.info(
        "genesis %s: %d nodes, f=%d, threshold=%d, hash %s",
        path,
        len(g.nodes),
        g.f,
        g.threshold,
        g.hash,
    )
    return g


# release


def _local(a: argparse.Namespace) -> str | None:
    """--node, else $MATRIX_NODE, else 127.0.0.1:7700 (the laptop's own builder)."""
    local = a.node or os.environ.get("MATRIX_NODE") or "127.0.0.1:7700"
    if not _HOSTPORT.fullmatch(local):
        _err(f"--node must be HOST:PORT, got {local!r}")
        return None
    log.info("local builder: %s", local)
    return local


def cmd_release(a: argparse.Namespace) -> int:
    g = _load(a)
    local = _local(a)
    if g is None or local is None:
        return EXIT_ERROR
    return asyncio.run(release_job(a, g, local))


async def release_job(a: argparse.Namespace, g: Genesis, local: str) -> int:
    """`matrix release` after the genesis and the local builder are known: load the release key,
    then sign, submit, wait and download. Shared by the CLI and the TUI."""
    key = a.key or str(Path.home() / ".matrix" / "keys" / "release.key")
    try:
        sk = load_key(key)
    except (OSError, ValueError) as e:
        _err(f"cannot load key: {e}")
        return EXIT_ERROR
    log.info("release: key %s loaded", key)
    return await _release(a, g, sk, local)


def release_required(g: Genesis, online: int) -> int:
    """Matching attestations `matrix release` insists on before it writes a certificate: the
    genesis threshold f+1, or more than half of the builders online now if that is larger. It only
    ever raises the bar, so taking laptops offline cannot lower it below f+1. `matrix verify`
    stays offline and checks the genesis threshold only: "online" is not signed."""
    return max(g.threshold, online // 2 + 1)


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
    log.info("release: signing as %s; request body %s", signer.id, body)
    env = make_envelope("release", signer.id, body, sk, g)
    rid = request_id(body)
    _out(f"request {rid} {a.repo}@{a.tag}")
    peers, book = await open_client(g, local)
    try:
        accepted = await _submit_quorum(peers, g, env, _online(g, book))
        log.info(
            "release: %d operators accepted (need %d); polling every %ds for up to %ds",
            accepted,
            g.f + 1,
            RELEASE_POLL_S,
            a.wait,
        )
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
            online = len(_online(g, book))
            need = release_required(g, online)
            agree = sum(r == v.hash for r in v.results.values()) if v.state == "AGREED" else 0
            enough = v.state == "AGREED" and agree >= need
            log.info(
                "release: poll: %d builders answered, %d attestations, verdict %s, "
                "%d agree, need %d (%d online)",
                len(answered),
                len(union),
                v.state,
                agree,
                need,
                online,
            )
            if enough and (got is None or got[0] != v.hash):
                data = await _download(peers, v)
                got = (v.hash, data) if data is not None else None
            settled = v.state != "PENDING" and (v.state != "AGREED" or (enough and got is not None))
            if (settled and len(ever) > g.f) or time.monotonic() >= deadline:
                break
            await asyncio.sleep(RELEASE_POLL_S)
    finally:
        await peers.close()

    _print_table(g, rid, v)
    if len(ever) <= g.f:
        _err(f"only {len(ever)} builders answered; need at least {g.f + 1}")
        return EXIT_ERROR
    if v.state == "AGREED" and enough and got is not None:
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
    if v.state == "AGREED" and not enough:
        _out(
            f"PENDING: {agree} of {online} online builders agree on {v.hash}; "
            f"need {need} (the genesis threshold {g.threshold}, or more than half of those online)"
        )
        return EXIT_PENDING
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
        sent = []
        for dest in broadcast_targets():
            try:
                self.transport.sendto(data, (dest, self.port))
                sent.append(dest)
            except OSError as e:  # no network right now: the next round retries
                log.debug("udp tx to %s failed: %s", dest, e)
        log.debug("udp tx %d bytes to %s", len(data), sent)

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()


def _stdin_lines() -> "tuple[asyncio.Queue[str], threading.Event]":
    """Lines typed by the user, read on a daemon thread so the event loop keeps listening and
    an interrupted ceremony never waits for Enter on exit. EOF arrives as "". Setting the event
    stops the reader: the dashboard that follows the ceremony needs stdin to itself."""
    loop = asyncio.get_running_loop()
    q: asyncio.Queue[str] = asyncio.Queue()
    stop = threading.Event()

    def put(line: str) -> None:
        try:
            loop.call_soon_threadsafe(q.put_nowait, line)
        except RuntimeError:
            pass  # the loop already closed

    def reader() -> None:
        buf = b""
        try:
            fd = sys.stdin.fileno()
            while not stop.is_set():
                if not select.select([fd], [], [], 0.2)[0]:
                    continue  # wakes up to notice `stop`
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    put(line.decode("utf-8", "replace") + "\n")
        except (OSError, ValueError):
            pass  # stdin closed or not readable: treated as end of input
        if stop.is_set():
            return
        if buf:
            put(buf.decode("utf-8", "replace"))
        put("")

    threading.Thread(target=reader, daemon=True).start()
    return q, stop


async def ceremony(
    params: dict,
    name: str,
    sk: Any,
    release_sk: Any,
    bus: Any,
    ask,
    timeout: float = CEREMONY_TIMEOUT_S,
    interval: float = FOUNDER_INTERVAL_S,
    drain=lambda: None,
) -> tuple[dict, list[dict], bytes] | None:
    """Found the network with the other laptops. Returns (genesis, endorsements, own endorse)
    or None if aborted; nothing is written here. `ask(kind)` returns the next typed line for the
    question `kind` ("seal": Enter, "confirm": y/N). `drain()` drops lines typed ahead."""
    loop = asyncio.get_running_loop()
    nid, me_pub = params["name"], pubkey_hex(sk)
    own = make_founder(params, name, sk, release_sk)
    founders: dict[str, Founder] = {me_pub: parse_founder(own, nid)}
    endorses: dict[str, Endorse] = {}
    mine = params_hash(params)
    sealed: dict[str, str] = {}  # after the seal: genesis id -> pubkey, the only keys that count
    # pubkey -> {name: last time seen}. One key under two names means two `matrix up` processes
    # on one laptop (e.g. a stale one): "latest wins" would then flip between names, and laptops
    # that seal at different moments would build different genesis files.
    names: dict[str, dict[str, float]] = {}
    warned: set[tuple[str, str]] = set()

    def split_keys() -> dict[str, list[str]]:
        now = loop.time()
        live = {
            pub: sorted(n for n, t in seen.items() if now - t <= ONLINE_WINDOW_S)
            for pub, seen in names.items()
        }
        return {pub: ns for pub, ns in live.items() if len(ns) > 1}

    rx = {"own": 0, "others": 0, "ignored": 0}  # datagram counts, for the debug summary
    log.info(
        "ceremony: network %r, name %s, node key %s, params hash %s, announce every %ss, timeout %ss",
        nid,
        name,
        me_pub[:8],
        mine[:8],
        interval,
        timeout,
    )

    def show(f: Founder) -> None:
        flag = "" if f.params_hash == mine else "  params MISMATCH (different network.toml)"
        _out(f"  + {f.id:<24} {f.pubkey[:8]}{flag}")

    proposals: dict[str, Seal] = {}  # proposer key -> its latest seal proposal (never our own)
    shown: dict[str, tuple] = {}  # proposer key -> what the screen last said about it

    def judge(s: Seal) -> tuple[str, list[str]]:
        """How a proposal fits what this laptop has heard: ("ok" | "waiting" | "refused", notes).
        A proposal can arrive before the founders it lists, or after a message was lost, so this
        runs again on every change instead of deciding once."""
        listed = {k: n for n, k in s.founders}
        notes = []
        for k, n in listed.items():
            f = founders.get(k)
            if f is None:
                notes.append(f"not heard yet: {n} {k[:8]} (waiting for its announcement)")
            elif f.id != n:
                notes.append(f"key {k[:8]} is {f.id} here, the proposal says {n}")
        if notes:
            return "waiting", notes
        fs = [founders[k] for k in listed]
        problem = seal_problem(params, fs, me_pub)
        if problem is None and parse_genesis(ceremony_genesis(params, fs)).hash != s.genesis_hash:
            problem = "same list but a different genesis: different network.toml?"
        if problem:
            notes.append(problem)
        for k, f in founders.items():
            if k not in listed:
                notes.append(f"you also hear {f.id} {k[:8]}, which the proposal lacks")
        for pub, ns in split_keys().items():
            notes.append(f"key {pub[:8]} announces as {' and '.join(ns)} (two `matrix up`?)")
        return ("refused" if notes else "ok"), notes

    def review() -> None:
        """Tell the user about each proposal, again whenever what we can say about it changes."""
        if sealed:
            return
        for pub, s in proposals.items():
            state, notes = judge(s)
            if shown.get(pub) == (s.genesis_hash, state, tuple(notes)):
                continue
            shown[pub] = (s.genesis_hash, state, tuple(notes))
            who = next((n for n, k in s.founders if k == pub), "?")
            _out(
                f">> {who} ({pub[:8]}) proposes to seal {len(s.founders)} founders, "
                f"short code {short_code(s.genesis_hash)}:"
            )
            for n, k in s.founders:
                _out(f"     {n:<24} {k[:8]}")
            for note in notes:
                _out(f"   ! {note}")
            if state == "ok":
                if len(s.founders) < 4:
                    _out(
                        "   WARNING: fewer than 4 founders gives f=0: one builder alone certifies."
                    )
                _out("   Same list as yours. Type y to accept once the short code matches aloud.")
            else:
                _out("   Cannot accept yet." if state == "waiting" else "   Cannot accept this.")

    def on_datagram(data: bytes, src) -> None:
        f = parse_founder(data, nid)
        if f is not None:
            prev = founders.get(f.pubkey)
            founders[f.pubkey] = f  # latest wins
            names.setdefault(f.pubkey, {})[f.id] = loop.time()
            for pub, ns in split_keys().items():
                if (pub, ns[-1]) not in warned and pub == f.pubkey:
                    warned.add((pub, ns[-1]))
                    _out(
                        f"  ! key {pub[:8]} announces as {' and '.join(ns)}: "
                        "is `matrix up` running twice on one laptop? Stop one of them."
                    )
            own_echo = f.pubkey == me_pub
            rx["own" if own_echo else "others"] += 1
            if not own_echo:  # our own echoes arrive once per interface: counted, not logged
                log.debug("ceremony: founder %s (%s) from %s", f.id, f.pubkey[:8], src[0])
            if prev is None or (prev.id, prev.params_hash) != (f.id, f.params_hash):
                show(f)
                review()  # a proposal may have been waiting for exactly this founder
            return
        s = parse_seal(data, nid)
        if s is not None:
            rx["own" if s.signer == me_pub else "others"] += 1
            if s.signer != me_pub:
                log.debug(
                    "ceremony: seal by %s for %s from %s", s.signer[:8], s.genesis_hash[:8], src[0]
                )
                proposals.pop(s.signer, None)  # newest last, so `y` takes the latest
                proposals[s.signer] = s
                review()
            return
        # Before the seal, founders' keys; after it, only the sealed genesis keys, so a late
        # rogue using a member's name cannot shadow that member's endorsement.
        e = parse_endorse(data, sealed or {x.id: x.pubkey for x in founders.values()})
        if e is not None:
            endorses[e.signer] = e
            rx["others" if e.signer != me_pub else "own"] += 1
            log.debug(
                "ceremony: endorse by %s for %s from %s", e.signer[:8], e.genesis_hash[:8], src[0]
            )
        else:
            rx["ignored"] += 1
            log.debug(
                "ceremony: ignored %d bytes from %s (not a founder or endorse of this network)",
                len(data),
                src[0],
            )

    await bus.open(on_datagram)
    sending = [own]

    async def announce() -> None:
        rounds = 0
        while True:
            for msg in sending:
                bus.send(msg)
            rounds += 1
            log.debug(
                "ceremony: round %d: sent %d, received own echo %d / from others %d / ignored %d; %d founders known",
                rounds,
                len(sending),
                rx["own"],
                rx["others"],
                rx["ignored"],
                len(founders),
            )
            if rounds == 5 and not rx["others"]:
                log.warning(
                    "ceremony: %ds without a datagram from any other laptop%s: check UDP %d "
                    "(firewall, same Wi-Fi, client isolation; docs/OPS.md §5)",
                    int(rounds * interval),
                    "" if rx["own"] else " and not even our own echo",
                    DISCOVERY_PORT,
                )
            await asyncio.sleep(interval)

    announcer = asyncio.create_task(announce())
    try:
        _out(f"Founding network {nid!r} as {name} ({me_pub[:8]}). Founders found:")
        show(founders[me_pub])
        _out("Press Enter to seal when every laptop is listed.")
        proposal: bytes | None = None
        while True:
            line = await ask("seal")
            log.debug("ceremony: input %r (%d founders listed)", line.strip(), len(founders))
            if not line:
                _err("stdin closed: the ceremony needs a terminal")
                return None
            if line.strip().lower() in ("y", "yes"):  # accept a proposal from another laptop
                s = next(
                    (s for s in reversed(list(proposals.values())) if judge(s)[0] == "ok"), None
                )
                if s is None:
                    _out("no proposal to accept yet: one laptop presses Enter to propose")
                    continue
                fs = [founders[k] for _, k in s.founders]
                raw = ceremony_genesis(params, fs)
                g = parse_genesis(raw)
                _out(f"Accepted the proposal with {len(fs)} founders:")
                log.info("ceremony: accepted proposal %s of %s", g.hash, s.signer[:8])
                break
            problem = seal_problem(params, list(founders.values()), me_pub)
            for pub, ns in split_keys().items():
                problem = problem or (
                    f"key {pub[:8]} announces as {' and '.join(ns)} "
                    "(two `matrix up` on one laptop?): stop one, then Enter again"
                )
            if problem is not None:
                log.info("ceremony: seal refused: %s", problem)
                _out(f"cannot seal yet: {problem}")
                continue
            fs = list(founders.values())  # frozen: later founders do not change our proposal
            raw = ceremony_genesis(params, fs)
            g = parse_genesis(raw)
            log.info(
                "ceremony: proposing %d founders %s, genesis hash %s",
                len(fs),
                [f"{f.id}:{f.pubkey[:8]}" for f in fs],
                g.hash,
            )
            _out(f"Proposing to seal {len(fs)} founders:")
            for n in g.nodes:
                _out(f"  {n.id:<24} {n.pubkey[:8]}")
            _out(f"Short code: {short_code(g.hash)}")
            if g.f == 0:
                _out(
                    f"WARNING: {len(fs)} founders give f=0: ONE builder alone certifies a release, "
                    "so no builder can be a faulty or malicious one. Use 4 or more laptops for f=1."
                )
            # Sent again every round with the founder announcements: a lost datagram only delays.
            proposal = make_seal(nid, sk, fs, g.hash)
            sending.append(proposal)
            bus.send(proposal)
            drain()  # an extra Enter pressed while proposing must not answer the y/N question
            _out("The others are asked to accept it. Read the short code aloud. Confirm? [y/N]")
            answer = ""
            while not answer.strip():  # a stray Enter is not an answer: only y or n are
                answer = await ask("confirm")
                if not answer:
                    _err("stdin closed: the ceremony needs a terminal")
                    return None
                if not answer.strip():
                    _out("Type y to confirm, or n to withdraw the proposal.")
            log.info("ceremony: short code answer %r", answer.strip())
            if answer.strip().lower() == "y":
                break
            sending.remove(proposal)  # withdrawn: back to listening, or accept another proposal
            proposal = None
            _out("Proposal withdrawn. Enter proposes again; y accepts another laptop's proposal.")
        if proposal is None:  # accepted, not proposed: show what we are about to endorse
            for n in g.nodes:
                _out(f"  {n.id:<24} {n.pubkey[:8]}")
            _out(f"Short code: {short_code(g.hash)}")

        sealed.update({n.id: n.pubkey for n in g.nodes})
        endorses = {k: e for k, e in endorses.items() if parse_endorse(e.raw, sealed)}
        me = next(n for n in g.nodes if n.pubkey == me_pub)
        endorse = make_endorse(g, me, sk)
        endorses[me.id] = parse_endorse(endorse, {me.id: me_pub})
        sending.append(endorse)
        bus.send(endorse)
        log.info(
            "ceremony: endorsed genesis %s, waiting for %d endorsements", g.hash[:16], len(g.nodes)
        )
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
                log.info("ceremony: endorsements from %s", sorted(e["signer"] for e in ok))
                _out(f"waiting for every laptop to confirm: {seen}/{len(ids)}")
            if loop.time() > deadline:
                _err("not every laptop confirmed in time: nothing written")
                return None
            await asyncio.sleep(0.2)
        log.info("ceremony: all %d endorsements verified", len(ids))
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
        log.info("keys: generated %s (mode 0600, never leaves this laptop)", path)
    else:
        log.info("keys: using existing %s", path)
    return load_key(str(path))


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)
    log.info("wrote %s (%d bytes)", path, len(data))


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
            log.info("refound: moved %s to %s", home / name, dest / name)
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
    log.info("founded network found in %s: genesis %s, pin and endorsements verified", home, g.hash)
    return g


async def _keep_endorsing(data: bytes, seconds: float) -> None:
    """Laptops that confirmed later can still finish their ceremony (L42). Send only: the node
    owns the discovery port now."""
    loop = asyncio.get_running_loop()
    with udp_socket(None) as sock:
        end = loop.time() + seconds
        while loop.time() < end:
            for dest in broadcast_targets():
                try:
                    sock.sendto(data, (dest, DISCOVERY_PORT))
                    log.debug(
                        "late endorse: udp tx %d bytes to %s:%d", len(data), dest, DISCOVERY_PORT
                    )
                except OSError as e:
                    log.debug("late endorse: udp tx to %s failed: %s", dest, e)
            await asyncio.sleep(FOUNDER_INTERVAL_S)


async def _quiet_ok(*argv: str) -> bool:
    log.debug("exec: %s", " ".join(argv))
    p = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
    )
    rc = await p.wait()
    log.debug("exec: rc=%d", rc)
    return rc == 0


async def _docker_ready(images: Any) -> bool:
    """Docker is reachable and every pinned toolchain image is present, pulled now if missing.
    Without this a laptop's first build would spend its whole timeout downloading the image (or
    fail on a stopped Docker) and silently abstain."""
    try:
        if not await _quiet_ok("docker", "version"):
            _err("cannot reach Docker: start Docker Desktop or the docker service (docs/OPS.md §4)")
            return False
    except FileNotFoundError:
        _err("docker not found: install Docker first (docs/OPS.md §4)")
        return False
    for image in sorted(set(images)):
        present = await _quiet_ok("docker", "image", "inspect", image)
        log.info("docker: image %s %s", image, "present" if present else "missing")
        if present:
            continue
        _out(f"pulling the pinned Go toolchain {image} (once per laptop)...")
        p = await asyncio.create_subprocess_exec(
            "docker", "pull", "--platform", "linux/amd64", image
        )
        if await p.wait() != 0:
            _err(f"docker pull {image} failed: check the internet connection, then retry")
            return False
    log.info("docker: reachable, %d pinned image(s) present", len(set(images)))
    _out(f"build isolation: {(await isolation())[1]}")
    return True


def cmd_up(a: argparse.Namespace) -> int:
    home = Path(a.home).expanduser() if a.home else Path.home() / ".matrix"
    log.info(
        "up: home %s, name %s, refound %s, advertise %s",
        home,
        a.name or "(hostname)",
        a.refound,
        a.advertise,
    )
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
        log.info("up: %s exists, skipping the founding ceremony", home / "genesis.json")
        if _check_founded(home) is None:
            return EXIT_ERROR
    else:
        log.info("up: no founded network (or --refound): running the founding ceremony")
        # ./network.toml wins (a deliberately different network); else the checkout this
        # `matrix` was installed from, so `matrix up` works from any directory.
        path = Path("network.toml")
        if not path.exists():
            path = _CHECKOUT / "network.toml"
        try:
            params = load_network(str(path))
            log.info("network.toml loaded from %s: %s", path.resolve(), params)
        except NetworkError as e:
            _err(f"{e} (run `matrix up` from the repo checkout)")
            return EXIT_ERROR
        name = a.name or default_name()
        if not valid_name(name):
            _err(f"hostname gives an invalid name {name!r}: pass --name")
            return EXIT_ERROR
        # before the ceremony, so no founder waits for this laptop's download mid-founding
        log.info("up: checking Docker and the pinned images")
        if not await _docker_ready(params["allowed_images"].values()):
            return EXIT_ERROR
        home.mkdir(mode=0o700, parents=True, exist_ok=True)
        log.info("up: loading or creating keys in %s", keys)
        try:
            sk, release_sk = _ensure_key(keys / "node.key"), _ensure_key(keys / "release.key")
        except (OSError, ValueError) as e:
            _err(f"cannot create or load keys in {keys}: {e}")
            return EXIT_ERROR
        ip = local_ip()
        log.info(
            "up: LAN address %s; founders are broadcast to %s (UDP %d)",
            ip,
            broadcast_targets(),
            DISCOVERY_PORT,
        )
        stop_reading = None
        try:
            lines, stop_reading = _stdin_lines()

            def drain() -> None:
                eof = False
                while not lines.empty():
                    eof |= lines.get_nowait() == ""
                if eof:
                    lines.put_nowait("")  # keep end-of-input, or the y/N prompt would wait forever

            result = await ceremony(
                params, name, sk, release_sk, UdpBus(), lambda _: lines.get(), drain=drain
            )
        except OSError as e:
            _err(f"cannot use UDP port {DISCOVERY_PORT}: {e} (is `matrix up` already running?)")
            return EXIT_ERROR
        finally:
            if stop_reading is not None:
                stop_reading.set()
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
    log.info("up: genesis %s loaded, %d nodes", g.hash, len(g.nodes))
    try:
        pub = pubkey_hex(load_key(str(keys / "node.key")))
    except (OSError, ValueError) as e:
        _err(f"cannot load {keys / 'node.key'}: {e}")
        return EXIT_ERROR
    me = next((n for n in g.nodes if n.pubkey == pub), None)
    if me is None:
        _err("this laptop's node key is not in the founded genesis")
        return EXIT_ERROR
    log.info("up: this laptop is %s in genesis", me.id)
    if not await _docker_ready(g.allowed_images.values()):
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
    log.info("up: starting the node: %s", vars(args))
    _out(f"{me.id}: builder starting on 0.0.0.0:7700 (Ctrl-C to stop)")
    # Just founded, on a real terminal: show the dashboard now. Later runs keep the plain
    # foreground builder (`matrix tui` in a second terminal, as before). With --verbose the
    # console is the log: every step and the build output of this laptop scroll by, so the
    # full-screen dashboard (which would hide them) stays off.
    verbose = getattr(a, "verbose", False)
    show_tui = endorse is not None and sys.stdin.isatty() and sys.stdout.isatty() and not verbose
    if verbose and endorse is not None:
        _out("verbose: logs stay on this console; run `matrix tui` in a second terminal.")
    try:
        if show_tui:
            await _node_and_tui(node, args, g, "127.0.0.1:7700", str(home))
        else:
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


async def _wait_listening(local: str, task: "asyncio.Task", seconds: float = 30) -> None:
    """Until the builder's HTTP port answers (or the builder task ends), so the dashboard's first
    frame is not "no builder at ..." while Docker is still being checked."""
    host, _, port = local.rpartition(":")
    deadline = time.monotonic() + seconds
    while not task.done() and time.monotonic() < deadline:
        try:
            _, w = await asyncio.open_connection(host, int(port))
            w.close()
            return
        except OSError:
            await asyncio.sleep(0.2)


async def _node_and_tui(
    node: Any, args: argparse.Namespace, g: Genesis, local: str, home: str = "~/.matrix"
) -> None:
    """Run the builder and the dashboard side by side on one terminal. If the builder stops the
    dashboard closes; if the user quits the dashboard the builder keeps running in the foreground.
    The dashboard's reset key stops the builder, wipes its data dir and starts it again."""
    from .tui import MatrixTui, play_intro

    state = {"task": asyncio.create_task(node.run(args)), "resetting": False}
    await _wait_listening(local, state["task"])
    if state["task"].done():
        state["task"].result()  # it stopped before listening: raise why
        return
    play_intro()

    async def reset() -> str:
        """Delete requests, attestations, logs and artifacts of this laptop (keys and genesis
        stay), then start the builder again. Peers keep their copies and sync them back."""
        state["resetting"] = True
        failure: OSError | None = None
        try:
            old = state["task"]
            old.cancel()
            await asyncio.gather(old, return_exceptions=True)
            try:
                shutil.rmtree(args.data)
            except FileNotFoundError:
                pass
            except OSError as e:
                failure = e  # the builder is restarted below either way
            state["task"] = asyncio.create_task(node.run(args))
            await _wait_listening(local, state["task"])
            if state["task"].done():
                state["task"].result()
        finally:
            state["resetting"] = False
        if failure is not None:
            raise failure
        log.info("reset: %s wiped, builder restarted", args.data)
        return (
            f"Deleted {args.data} and restarted the builder.\n"
            "Peers still hold their copies and will sync them back within seconds, "
            "unless every laptop resets at the same time."
        )

    app = MatrixTui(g, local, home=home, on_reset=reset)
    tui_task = asyncio.create_task(app.run_async())
    while True:
        done, _ = await asyncio.wait({state["task"], tui_task}, return_when=asyncio.FIRST_COMPLETED)
        if tui_task in done:
            break
        if state["resetting"]:
            await asyncio.sleep(0.1)  # the old builder task ends by design
            continue
        app.exit()
        await asyncio.gather(tui_task, return_exceptions=True)
        state["task"].result()  # raises the builder's error, if any
        return
    try:
        tui_task.result()
    except Exception as e:  # noqa: BLE001  a dashboard crash must not stop the builder
        _err(f"dashboard stopped: {e!r}")
    _out(
        "Dashboard closed; the builder keeps running here (Ctrl-C to stop; `matrix tui` reopens it)."
    )
    await state["task"]


# entry point

_RAW = argparse.RawDescriptionHelpFormatter

# The overview groups commands by what the person is doing; `matrix help` prints it.
_GROUPS = (
    ("Run this laptop's builder", ("up",)),
    ("Publish a release", ("release", "status", "evidence", "tui")),
    ("Check a binary (offline)", ("verify",)),
    ("Other", ("keygen", "help")),
)

_EXIT_CODES = """\
exit codes (only 0 is success; RFC §6.4):
  0  CERTIFIED (release), REPRODUCED (verify), settled (status)
  1  MISMATCH: the file is not the certified binary (verify)
  2  INVALID_CERT (verify), NOT_REPRODUCIBLE (release)
  3  PENDING: no quorum yet (release at --wait timeout, status)
  4  error: bad usage, unreachable builders, wrong key or genesis
  5  BUILD_FAILED: the builders confirmed a compile error (release)"""


def _globals(p: argparse.ArgumentParser, *, top: bool) -> None:
    """--genesis and --node, accepted before or after the command. After the command they
    default to SUPPRESS, so a value given before the command is not overwritten with None."""
    g = p.add_argument_group("global options")
    default = {} if top else {"default": argparse.SUPPRESS}
    g.add_argument(
        "--genesis",
        metavar="FILE",
        help="genesis.json of the network (default $MATRIX_GENESIS, else ~/.matrix/genesis.json)",
        **default,
    )
    g.add_argument(
        "--node",
        metavar="HOST:PORT",
        help="this laptop's builder, used to find the others "
        "(default $MATRIX_NODE, else 127.0.0.1:7700)",
        **default,
    )


def _command(
    sub: Any, name: str, summary: str, description: str, examples: str, exits: str = ""
) -> argparse.ArgumentParser:
    epilog = "examples:\n" + examples + (f"\n\nexit codes: {exits}" if exits else "")
    return sub.add_parser(
        name,
        prog=f"matrix {name}",
        add_help=False,
        help=summary,
        description=description,
        epilog=epilog,
        formatter_class=_RAW,
    )


def _options(s: argparse.ArgumentParser) -> Any:
    o = s.add_argument_group("options")
    o.add_argument("-h", "--help", action="help", help="show this help and exit")
    o.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,  # keeps a -v given before the command
        help="log every step to stderr (to ~/.matrix/verbose.log for tui)",
    )
    return o


def _overview(sub: Any) -> str:
    summaries = {a.dest: a.help for a in sub._choices_actions}
    lines = ["commands:"]
    for title, names in _GROUPS:
        lines.append(f"  {title}")
        lines += [f"    {n:<10}  {summaries[n]}" for n in names]
    lines += ["", _EXIT_CODES, "", "Run 'matrix help COMMAND' for a command's options."]
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="matrix",
        usage="matrix [-v] [--genesis FILE] [--node HOST:PORT] COMMAND [options]",
        description="Matrix: a Byzantine-tolerant release gate for Go binaries.\n"
        "Independent builders each build a tagged commit; a release is certified when f+1\n"
        "of them signed the same hash, and anyone can check the certificate offline.",
        formatter_class=_RAW,
    )
    _globals(p, top=True)
    p.add_argument(
        "-v", "--verbose", action="store_true", help="log every step to stderr, for debugging"
    )
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND", help=argparse.SUPPRESS)

    s = _command(
        sub,
        "up",
        "found the network on first run (ceremony), then run this laptop's builder",
        "Start this laptop's builder. On the first run (no ~/.matrix/genesis.json) it first runs\n"
        "the founding ceremony with the other laptops on the LAN: founders appear by UDP\n"
        "broadcast, Enter seals, everyone compares the short code aloud and confirms with y.\n"
        "Run it from the repo checkout, or any directory: the network parameters come from\n"
        "./network.toml if present, else from the checkout's network.toml.\n"
        "Ctrl-C stops the builder.",
        "  matrix up --name laptop-a     # first run: ceremony, then the builder\n"
        "  matrix up                     # later runs: no ceremony\n"
        "  matrix up --allow-faults --fault inject --patch examples/faults/backdoor.patch",
        "0 stopped cleanly, 4 error (ceremony aborted, wrong keys, port in use)",
    )
    o = _options(s)
    o.add_argument(
        "--name",
        metavar="NAME",
        help="this laptop's name in genesis, [A-Za-z0-9_-]{1,24} (default: from the hostname)",
    )
    o.add_argument(
        "--home", metavar="DIR", help="state directory: keys, genesis, data (default ~/.matrix)"
    )
    o.add_argument(
        "--refound",
        action="store_true",
        help="found a new network; the old one moves to DIR/old-<short code>/",
    )
    o.add_argument(
        "--advertise",
        metavar="IPv4:PORT",
        help="address put in hellos (default: this laptop's LAN address, port 7700)",
    )
    f = s.add_argument_group("demo faults (inert without --allow-faults; never more than f)")
    f.add_argument("--allow-faults", action="store_true", help="enable a fault mode")
    f.add_argument(
        "--fault", choices=node._MODES, metavar="MODE", help="one of: " + ", ".join(node._MODES)
    )
    f.add_argument("--patch", metavar="FILE", help="patch applied before building (inject)")
    f.add_argument("--hash", metavar="HEX", help="64-hex hash to vote for (collude)")
    s.set_defaults(fn=cmd_up)

    s = _command(
        sub,
        "release",
        "sign a release, wait for a quorum, download the binary and its certificate",
        "Sign a release request for REPO@TAG at COMMIT with this laptop's release key, submit it\n"
        "until f+1 distinct operators accepted it, and wait for the verdict. On CERTIFIED,\n"
        "download the binary from a builder that voted for the certified hash and write\n"
        "DIR/NAME and DIR/NAME.matrix.json (the certificate).",
        "  matrix release --repo https://github.com/ChaoticNebula5/matrix-hello --tag v1.2.0 \\\n"
        "      --commit fb6881c6e2432fa107ef809af109a9a1344ed2c0 --out dist/v1.2.0",
        "0 CERTIFIED, 2 NOT_REPRODUCIBLE, 3 PENDING at --wait, 4 error, 5 BUILD_FAILED",
    )
    r = s.add_argument_group("required")
    r.add_argument("--repo", required=True, metavar="URL", help="https://github.com/OWNER/REPO")
    r.add_argument("--tag", required=True, metavar="TAG", help="git tag, e.g. v1.2.0")
    r.add_argument(
        "--commit", required=True, metavar="SHA", help="40-hex commit the tag points to (signed)"
    )
    o = _options(s)
    o.add_argument(
        "--key", metavar="FILE", help="release-signer key (default ~/.matrix/keys/release.key)"
    )
    o.add_argument(
        "--wait",
        type=int,
        default=600,
        metavar="SECONDS",
        help="give up with PENDING after this long (default 600)",
    )
    o.add_argument(
        "--out", default="dist", metavar="DIR", help="where to write the files (default dist)"
    )
    o.add_argument("--output", metavar="NAME", help="binary file name (default: the repo name)")
    _globals(s, top=False)
    s.set_defaults(fn=cmd_release)

    s = _command(
        sub,
        "status",
        "per-builder votes and the verdict for one request",
        "Ask the builders for their votes on one request and print the verdict, one row per\n"
        "builder. `matrix release` prints the request ID.",
        "  matrix status e573fc998fa7716c4681a03735619f1fb3fe13fd9e70acc56331511c169e67b8",
        "0 settled, 3 PENDING, 4 error",
    )
    s.add_argument("id", metavar="REQUEST_ID", help="64-hex request ID")
    _options(s)
    _globals(s, top=False)
    s.set_defaults(fn=cmd_status)

    s = _command(
        sub,
        "evidence",
        "signed proof of misbehaviour (equivocation) collected by the builders",
        "Print the evidence the builders collected, such as a builder that signed two different\n"
        "results for one request (EQUIVOCATION). Every proof is re-checked against the genesis\n"
        "public keys.",
        "  matrix evidence --since 1h",
        "0 ok (also with no evidence), 4 error",
    )
    o = _options(s)
    o.add_argument(
        "--since", default="1h", metavar="AGE", help="how far back: 30s, 10m, 1h, 2d (default 1h)"
    )
    _globals(s, top=False)
    s.set_defaults(fn=cmd_evidence)

    s = _command(
        sub,
        "tui",
        "live dashboard: builders, releases and evidence",
        "Full-screen live view of the network through this laptop's builder. Keys: b builders,\n"
        "r releases, Enter detail, l log (this laptop's builder only), e evidence, n new release,\n"
        "v verify, k keygen (forms that run `matrix release`, `verify` and `keygen`),\n"
        "x reset this laptop's builder data (only in the dashboard `matrix up` opens), q quit.",
        "  matrix tui",
        "0 on quit, 4 error",
    )
    _options(s)
    _globals(s, top=False)
    s.set_defaults(fn=cmd_tui)

    s = _command(
        sub,
        "verify",
        "check a binary against its certificate; needs no network",
        "Check, offline, that FILE is the binary the certificate certifies for the repo and tag\n"
        "YOU expect (never taken from the certificate), under the pinned genesis. Only exit 0\n"
        "means the file may be used.",
        "  matrix verify dist/v1.2.0/hello --cert dist/v1.2.0/hello.matrix.json \\\n"
        "      --repo https://github.com/ChaoticNebula5/matrix-hello --tag v1.2.0",
        "0 REPRODUCED, 1 MISMATCH, 2 INVALID_CERT, 4 error",
    )
    s.add_argument("file", metavar="FILE", help="the binary to check")
    r = s.add_argument_group("required")
    r.add_argument("--cert", required=True, metavar="FILE", help="its .matrix.json certificate")
    r.add_argument("--repo", required=True, metavar="URL", help="the repo you expect")
    r.add_argument("--tag", required=True, metavar="TAG", help="the tag you expect")
    o = _options(s)
    o.add_argument("--commit", metavar="SHA", help="also require this commit")
    o.add_argument(
        "--genesis-sha256",
        metavar="HEX",
        help="pinned genesis hash (default ~/.matrix/genesis.sha256)",
    )
    _globals(s, top=False)
    s.set_defaults(fn=cmd_verify)

    s = _command(
        sub,
        "keygen",
        "generate an Ed25519 key file and print its public key",
        "Write a new Ed25519 signing key (64-hex seed, mode 0600) and print its public key.\n"
        "`matrix up` creates this laptop's own keys; keygen is for extra keys, e.g. CI.",
        "  matrix keygen --out ~/.matrix/keys/ci-release.key",
        "0 written, 4 error",
    )
    r = s.add_argument_group("required")
    r.add_argument("--out", required=True, metavar="FILE", help="where to write the private key")
    _options(s)
    s.set_defaults(fn=cmd_keygen)

    s = _command(
        sub,
        "help",
        "show this overview, or one command's options",
        "Show the overview, or the full help of one command.",
        "  matrix help\n  matrix help release",
    )
    s.add_argument(
        "topic", nargs="?", choices=tuple(sub.choices), metavar="COMMAND", help="command to explain"
    )
    _options(s)

    def cmd_help(a: argparse.Namespace) -> int:
        _out((sub.choices[a.topic] if a.topic else p).format_help().rstrip("\n"))
        return EXIT_OK

    s.set_defaults(fn=cmd_help)
    p.epilog = _overview(sub)
    return p


def run(argv: list[str] | None = None) -> int:
    p = _parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:  # argparse exits 2 on bad usage; 2 means INVALID here, so remap
        return EXIT_OK if e.code == 0 else EXIT_ERROR
    if a.cmd is None:  # bare `matrix`: show what there is, but it is not a successful command
        sys.stderr.write(p.format_help())
        return EXIT_ERROR
    verbose = getattr(a, "verbose", False)
    logfile = None
    if verbose and a.cmd == "tui":  # stderr would garble the full-screen UI
        logfile = Path.home() / ".matrix" / "verbose.log"
        logfile.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _err(f"verbose log: {logfile}")
    node.configure_logging(verbose, str(logfile) if logfile else None)
    log.info("matrix %s: %s", a.cmd, {k: v for k, v in vars(a).items() if k != "fn"})
    try:
        return a.fn(a)
    except Exception as e:  # noqa: BLE001  fail closed: an unexpected error is never success
        _err(f"unexpected error: {e!r}")
        return EXIT_ERROR


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
