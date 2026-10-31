"""`matrix` CLI: keygen, release, status, verify, evidence, tui (RFC §7.11, LLD §3.13)."""

import argparse
import asyncio
import hashlib
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any

from aiohttp import ClientError

from .canon import canonical_json
from .crypto import keygen, load_key, pubkey_hex
from .genesis import Genesis, GenesisError, Node, load_genesis
from .model import make_envelope, parse_certificate, parse_envelope, request_id, valid_request
from .net import PeerClient
from .select import selected
from .verdict import Verdict, verdict

RELEASE_POLL_S = 2
MAX_ARTIFACT = 64 * 1024 * 1024  # RFC §4

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
        # O_EXCL: never overwrite an existing key; 0600: the seed is a secret (LLD §4).
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(seed + "\n")
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
    url = f"http://{node.addr}/v1/requests"
    headers = {"Content-Type": "application/json"}
    try:
        async with peers.session.post(url, data=canonical_json(env), headers=headers) as r:
            await r.read()
            return r.status == 202
    except (ClientError, OSError, TimeoutError):
        return False


def _submit_targets(g: Genesis) -> list[Node]:
    """First node of each of the first f+1 operators: one of them is honest and forwards it."""
    first: dict[str, Node] = {}
    for n in g.nodes:
        first.setdefault(n.operator, n)
    return list(first.values())[: g.f + 1]


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


def cmd_release(a: argparse.Namespace) -> int:
    g = _load(a)
    if g is None:
        return EXIT_ERROR
    try:
        sk = load_key(a.key)
    except (OSError, ValueError) as e:
        _err(f"cannot load key: {e}")
        return EXIT_ERROR
    return asyncio.run(_release(a, g, sk))


async def _release(a: argparse.Namespace, g: Genesis, sk: Any) -> int:
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
    peers = PeerClient(g, CLIENT)
    try:
        accepted = await asyncio.gather(*(_submit(peers, n, env) for n in _submit_targets(g)))
        if not any(accepted):
            _err("no builder accepted the request")
            return EXIT_ERROR
        deadline = time.monotonic() + a.wait
        ever: set[str] = set()
        got: tuple[str, bytes] | None = None  # (hash, artifact bytes)
        while True:
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
    return EXIT_ERROR if g is None else asyncio.run(_status(a.id, g))


async def _status(rid: str, g: Genesis) -> int:
    peers = PeerClient(g, CLIENT)
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
    if g is None:
        return EXIT_ERROR
    # Builders filter on their own clock; skew between laptops only widens or narrows the window.
    since = max(0, int(time.time()) - int(m[1]) * _UNITS[m[2]])
    return asyncio.run(_evidence(since, g))


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


async def _evidence(since: int, g: Genesis) -> int:
    peers = PeerClient(g, CLIENT)
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
    if g is None:
        return EXIT_ERROR
    node = a.node or g.nodes[0].id
    if g.node(node) is None:
        _err(f"{node} is not a genesis node")
        return EXIT_ERROR
    from .tui import run_tui  # lazy: Textual is only needed for this command

    return run_tui(g, node)


# entry point


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="matrix", description="Matrix release gate")
    p.add_argument("--genesis", help="genesis.json (default $MATRIX_GENESIS or ~/.matrix/)")
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
    s.add_argument("--key", required=True)
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
    s.add_argument("--node", help="builder to poll (default: first genesis node)")
    s.set_defaults(fn=cmd_tui)
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
