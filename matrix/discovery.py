"""Signed LAN discovery and the founding ceremony (RFC rev 5 §7.15, §7.16; LLD §3.10a).

Discovery locates members; it never changes membership, which is fixed by genesis (RFC D3).
Every message is one canonical JSON object per UDP datagram. Parsers never raise.
"""

import asyncio
import logging
import re
import socket
import struct
import sys
import time
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from nacl.signing import VerifyKey

from .canon import canonical_json, loads_strict, sha256_hex
from .crypto import pubkey_hex, sign, verify
from .genesis import Genesis, GenesisError, Node, parse_genesis

DISCOVERY_PORT = 7788
HELLO_INTERVAL_S = 5
ONLINE_WINDOW_S = 15
MAX_HELLO = 512
FOUNDER_INTERVAL_S = 2
CEREMONY_TIMEOUT_S = 300
MAX_CEREMONY = 1024
MAX_SEAL = 2048  # a seal lists every founder's name and key: about 140 bytes each
MAX_FOUNDERS = 16
FOUNDER_PREFIX = b"matrix/v1-founder\0"
BROADCAST = "255.255.255.255"

log = logging.getLogger(__name__)

_ENVELOPE = {"v", "type", "signer", "body", "sig"}
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_SIG = re.compile(r"[0-9a-f]{128}", re.ASCII)
_ADDR = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,5})", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9_-]{1,24}", re.ASCII)
_NETWORK = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)


def _m(rx: re.Pattern, v: object) -> bool:
    return isinstance(v, str) and rx.fullmatch(v) is not None


def valid_addr(a: object) -> bool:
    """`<IPv4>:<port>` with octets <= 255 and port 1-65535."""
    m = _ADDR.fullmatch(a) if isinstance(a, str) else None
    return m is not None and all(int(x) <= 255 for x in m.groups()[:4]) and 0 < int(m[5]) < 65536


def _load(data: Any, limit: int) -> tuple[dict | None, str]:
    """Strictly parsed envelope with the common checks, or (None, reason)."""
    if isinstance(data, dict):
        try:
            if len(canonical_json(data)) > limit:
                return None, "size"
        except Exception:  # noqa: BLE001  floats or odd types: hostile input never raises
            return None, "parse"
        raw = data
    elif isinstance(data, (bytes, bytearray)):
        if len(data) > limit:
            return None, "size"
        raw = loads_strict(bytes(data))
    else:
        return None, "parse"
    if (
        not isinstance(raw, dict)
        or set(raw) != _ENVELOPE
        or type(raw["v"]) is not int
        or raw["v"] != 1
        or not isinstance(raw["type"], str)
        or not isinstance(raw["body"], dict)
        or not _m(_SIG, raw["sig"])
    ):
        return None, "parse"
    return raw, ""


def _unsigned(raw: dict) -> dict:
    return {k: raw[k] for k in ("v", "type", "signer", "body")}


def _verify_raw(pub: str, msg: bytes, sig: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(pub)).verify(msg, bytes.fromhex(sig))
        return True
    except Exception:  # noqa: BLE001  never raises
        return False


# --- hello ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Hello:
    signer: str
    addr: str  # "<IPv4>:<port>"
    seq: int  # unix ms; strictly increasing per signer
    raw: dict


def make_hello(g: Genesis, me: Node, sk, addr: str, seq: int) -> bytes:
    unsigned = {
        "v": 1,
        "type": "hello",
        "signer": me.id,
        "body": {"genesis_hash": g.hash, "addr": addr, "seq": seq},
    }
    return canonical_json({**unsigned, "sig": sign(sk, g.hash, unsigned)})


def _check_hello(
    data: Any, g: Genesis, last_seq: Mapping[str, int] | None
) -> tuple[Hello | None, str]:
    """The receiver checks of RFC §7.15, cheapest first, so per-packet work is bounded."""
    try:
        raw, reason = _load(data, MAX_HELLO)  # 1: size, strict parse, exact keys
        if raw is None:
            return None, reason
        body = raw["body"]
        if (
            raw["type"] != "hello"
            or set(body) != {"genesis_hash", "addr", "seq"}
            or not valid_addr(body["addr"])
            or type(body["seq"]) is not int
            or body["seq"] < 0
            or not isinstance(raw["signer"], str)
        ):
            return None, "parse"
        node = g.node(raw["signer"])
        if node is None:  # 2: strangers are dropped before any signature work
            return None, "signer"
        if body["genesis_hash"] != g.hash:  # 3
            return None, "genesis"
        if body["seq"] <= (last_seq or {}).get(raw["signer"], -1):  # 4: anti-replay
            return None, "replay"
        if not verify(node.pubkey, g.hash, _unsigned(raw), raw["sig"]):  # 5
            return None, "sig"
        return Hello(raw["signer"], body["addr"], body["seq"], raw), ""
    except Exception:  # noqa: BLE001  hostile input must never raise (invariant 1)
        return None, "parse"


def parse_hello(data: Any, g: Genesis, last_seq: Mapping[str, int] | None = None) -> Hello | None:
    return _check_hello(data, g, last_seq)[0]


_SIOCGIFBRDADDR = {"linux": 0x8919, "darwin": 0xC0206923}


def broadcast_targets() -> list[str]:
    """255.255.255.255 plus each interface's own broadcast address (e.g. 172.16.223.255).

    The limited broadcast leaves through the default route only, and some networks drop it but
    forward the directed one. Linux and macOS (ioctl); elsewhere only the limited broadcast."""
    out = [BROADCAST]
    req = _SIOCGIFBRDADDR.get(sys.platform)
    if req is None:
        return out
    import fcntl

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _, name in socket.if_nameindex():
            try:
                res = fcntl.ioctl(s.fileno(), req, struct.pack("256s", name.encode()[:15]))
            except OSError:
                continue  # no broadcast address: loopback, tunnels
            ip = socket.inet_ntoa(res[20:24])  # sockaddr_in.sin_addr inside struct ifreq
            if ip != "0.0.0.0" and ip not in out:
                out.append(ip)
    log.debug("broadcast targets: %s", out)
    return out


def local_ip() -> str | None:
    """The LAN address the OS would send from (UDP connect sends nothing)."""
    for target in ((BROADCAST, DISCOVERY_PORT), ("192.0.2.1", 9)):  # TEST-NET-1: default route
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.connect(target)
                ip = s.getsockname()[0]
        except OSError as e:
            log.debug("local_ip: route to %s failed: %s", target[0], e)
            continue
        if ip == "0.0.0.0" or ip.startswith("127."):
            log.debug("local_ip: route to %s leaves from %s, not a LAN address", target[0], ip)
        if ip != "0.0.0.0" and not ip.startswith("127."):
            return ip
    log.debug("local_ip: no LAN address found")
    return None


class AddressBook:
    """Latest verified address per member, in memory only. Never adds or removes members."""

    def __init__(self, g: Genesis, clock=time.time):
        self.g, self.clock = g, clock
        self.seqs: dict[str, int] = {}  # last accepted seq per signer (check 4)
        self._entries: dict[str, tuple[str, float, dict]] = {}  # id -> (addr, last_seen, raw)

    def accept(self, data: Any) -> Hello | None:
        h, reason = _check_hello(data, self.g, self.seqs)
        if h is None:
            log.debug("hello.reject reason=%s", reason)
            return None
        self.update(h)
        log.debug("hello.accept id=%s addr=%s seq=%d", h.signer, h.addr, h.seq)
        return h

    def update(self, h: Hello) -> bool:
        """Store a verified hello; True if this member's address is new or changed."""
        if h.seq <= self.seqs.get(h.signer, -1):
            return False
        prev = self._entries.get(h.signer)
        self.seqs[h.signer] = h.seq
        self._entries[h.signer] = (h.addr, self.clock(), h.raw)
        return prev is None or prev[0] != h.addr

    def addr(self, node_id: str) -> str | None:
        e = self._entries.get(node_id)
        return e[0] if e else None

    def online(self, node_id: str, now: float) -> bool:
        e = self._entries.get(node_id)
        return e is not None and now - e[1] < ONLINE_WINDOW_S

    def hellos(self) -> list[dict]:
        return [self._entries[k][2] for k in sorted(self._entries)]


def udp_socket(port: int | None) -> socket.socket:
    """Broadcast-capable UDP socket; bound to 0.0.0.0:port unless port is None (send only)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if port is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if sys.platform == "darwin" and hasattr(socket, "SO_REUSEPORT"):
                # BSD sockets share a wildcard UDP port between processes only with
                # SO_REUSEPORT. Linux is left as is: there it would spread datagrams instead.
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind(("0.0.0.0", port))
        s.setblocking(False)
        log.debug("udp socket %s", f"bound to 0.0.0.0:{port}" if port is not None else "send-only")
        return s
    except OSError as e:
        log.debug("udp socket failed (port %s): %s", port, e)
        s.close()
        raise


class Datagrams(asyncio.DatagramProtocol):
    def __init__(self, on_datagram):
        self.on_datagram = on_datagram

    def datagram_received(self, data: bytes, addr) -> None:
        log.debug("udp rx %d bytes from %s:%d", len(data), addr[0], addr[1])
        try:
            self.on_datagram(data, addr)
        except Exception:  # a callback never takes the listener down
            log.exception("datagram handler failed")

    def error_received(self, exc: Exception) -> None:
        log.debug("udp error: %s", exc)


class Discovery:
    """Announces this node's signed address and learns the others' (RFC §7.15)."""

    def __init__(
        self,
        g: Genesis,
        me: Node,
        sk,
        book: AddressBook,
        listen_port: int,
        advertise: str | None = None,
        port: int = DISCOVERY_PORT,
        clock=time.time,
    ):
        self.g, self.me, self.sk, self.book = g, me, sk, book
        self.listen_port, self.advertise, self.port, self.clock = (
            listen_port,
            advertise,
            port,
            clock,
        )
        self.addr: str | None = None  # currently advertised
        self.last: bytes | None = None  # latest own hello (unicast replies resend it)
        self.last_sent = -1
        self.transport: asyncio.DatagramTransport | None = None
        self._online: set[str] = set()

    def _advertised(self) -> str | None:
        if self.advertise:
            return self.advertise
        ip = local_ip()
        return f"{ip}:{self.listen_port}" if ip else None

    def _send(self, data: bytes, dest: tuple[str, int]) -> None:
        try:
            if self.transport is not None:
                self.transport.sendto(data, dest)
                log.debug("udp tx %d bytes to %s:%d", len(data), *dest)
        except OSError as e:  # Wi-Fi off, no route: retried next round
            log.debug("%s hello.send_failed %s", self.me.id, e)

    def announce(self) -> None:
        seq = max(int(self.clock() * 1000), self.last_sent + 1)  # receivers drop repeated seqs
        self.last_sent = seq
        self.last = make_hello(self.g, self.me, self.sk, self.addr, seq)
        log.debug("%s hello.send addr=%s seq=%d", self.me.id, self.addr, seq)
        for dest in broadcast_targets():
            self._send(self.last, (dest, self.port))
        self.book.update(Hello(self.me.id, self.addr, seq, loads_strict(self.last)))
        now = self.clock()
        state = {
            n.id: "online"
            if self.book.online(n.id, now)
            else "offline"
            if self.book.addr(n.id)
            else "never-heard"
            for n in self.g.nodes
            if n.id != self.me.id
        }
        log.debug("%s members: %s", self.me.id, " ".join(f"{k}={v}" for k, v in state.items()))

    def on_datagram(self, data: bytes, src) -> None:
        h, reason = _check_hello(data, self.g, self.book.seqs)
        if h is None:
            why = "replay (our own echo, or an old hello)" if reason == "replay" else reason
            log.debug("%s datagram from %s dropped: %s", self.me.id, src[0], why)
            if reason not in ("replay", "parse"):  # own echo and ceremony traffic are routine
                log.info("%s hello.reject reason=%s from=%s", self.me.id, reason, src[0])
            return
        log.debug("%s hello.accept id=%s addr=%s seq=%d", self.me.id, h.signer, h.addr, h.seq)
        if self.book.update(h):
            log.info("%s peer.addr id=%s addr=%s", self.me.id, h.signer, h.addr)
            if self.last is not None and h.signer != self.me.id:
                self._send(self.last, (h.addr.rsplit(":", 1)[0], self.port))  # fast convergence

    def _track_online(self) -> None:
        now = self.clock()
        online = {n.id for n in self.g.nodes if n.id != self.me.id and self.book.online(n.id, now)}
        for nid in sorted(online - self._online):
            log.info("%s peer.online id=%s addr=%s", self.me.id, nid, self.book.addr(nid))
        for nid in sorted(self._online - online):
            log.info("%s peer.offline id=%s", self.me.id, nid)  # still a member: silent, not gone
        self._online = online

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        sock = udp_socket(self.port)  # a bind failure propagates: the node refuses to start
        log.info(
            "%s discovery: UDP %d, hello every %ds, online window %ds",
            self.me.id,
            self.port,
            HELLO_INTERVAL_S,
            ONLINE_WINDOW_S,
        )
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: Datagrams(self.on_datagram), sock=sock
        )
        try:
            next_at = 0.0
            while True:
                addr = self._advertised()
                if addr is None:
                    log.debug("%s no LAN address: not announcing (is Wi-Fi up?)", self.me.id)
                elif addr != self.addr or self.clock() >= next_at:
                    if addr != self.addr:
                        log.info("%s advertised address %s -> %s", self.me.id, self.addr, addr)
                    self.addr = addr
                    self.announce()
                    next_at = self.clock() + HELLO_INTERVAL_S
                self._track_online()
                await asyncio.sleep(1)
        finally:
            self.transport.close()
            self.transport = None


# --- founding ceremony ------------------------------------------------------------------------


class NetworkError(Exception):
    pass


_NETWORK_KEYS = {
    "name", "allowed_repos", "allowed_images", "allowed_goos", "allowed_goarch",
    "build_timeout_s", "request_ttl_s", "sync_interval_s",
}  # fmt: skip


def load_network(path: str) -> dict:
    """The [network] table of network.toml. Value rules are left to parse_genesis."""
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise NetworkError(f"cannot read {path}: {e}") from e
    net = doc.get("network") if set(doc) == {"network"} else None
    if not isinstance(net, dict) or set(net) != _NETWORK_KEYS:
        raise NetworkError(f"{path} must hold exactly [network] with {sorted(_NETWORK_KEYS)}")
    if not _m(_NETWORK, net["name"]):
        raise NetworkError("network name must match [A-Za-z0-9_.-]{1,64}")
    for k in ("allowed_repos", "allowed_goos", "allowed_goarch"):
        if not isinstance(net[k], list) or not all(isinstance(x, str) for x in net[k]):
            raise NetworkError(f"{k} must be a list of strings")
    images = net["allowed_images"]
    if not isinstance(images, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in images.items()
    ):
        raise NetworkError("allowed_images must be a table of strings")
    for k in ("build_timeout_s", "request_ttl_s", "sync_interval_s"):
        if type(net[k]) is not int:
            raise NetworkError(f"{k} must be an integer")
    return dict(net)


def params_hash(params: dict) -> str:
    return sha256_hex(canonical_json(params))


def default_name() -> str:
    name = re.sub(r"[^a-z0-9_-]", "-", socket.gethostname().lower())[:24]
    return name or "laptop"


def valid_name(name: object) -> bool:
    return _m(_NAME, name)


def founder_bytes(network_id: str, unsigned: dict) -> bytes:
    # Own prefix: a founder signature can never be replayed as an envelope, and the reverse.
    return FOUNDER_PREFIX + network_id.encode("ascii") + b"\0" + canonical_json(unsigned)


def _release_proof(pub: str, release_pub: str) -> dict:
    return {"pubkey": pub, "release_pubkey": release_pub}


@dataclass(frozen=True)
class Founder:
    id: str
    pubkey: str
    release_pubkey: str
    params_hash: str
    raw: dict


def make_founder(params: dict, name: str, sk, release_sk) -> bytes:
    nid, pub, rpub = params["name"], pubkey_hex(sk), pubkey_hex(release_sk)
    # The release key signs too: a founder cannot list someone else's release key as its own.
    proof = release_sk.sign(founder_bytes(nid, _release_proof(pub, rpub))).signature.hex()
    body = {
        "network_id": nid,
        "id": name,
        "pubkey": pub,
        "release_pubkey": rpub,
        "release_sig": proof,
        "params_hash": params_hash(params),
    }
    unsigned = {"v": 1, "type": "founder", "signer": pub, "body": body}
    sig = sk.sign(founder_bytes(nid, unsigned)).signature.hex()
    return canonical_json({**unsigned, "sig": sig})


_FOUNDER_BODY = {"network_id", "id", "pubkey", "release_pubkey", "release_sig", "params_hash"}


def parse_founder(data: Any, network_id: str) -> Founder | None:
    try:
        raw, _ = _load(data, MAX_CEREMONY)
        if raw is None or raw["type"] != "founder":
            return None
        b = raw["body"]
        if (
            set(b) != _FOUNDER_BODY
            or b["network_id"] != network_id  # other networks on the hotspot are ignored
            or not valid_name(b["id"])
            or not all(_m(_HEX64, x) for x in (raw["signer"], b["pubkey"], b["release_pubkey"]))
            or not _m(_HEX64, b["params_hash"])
            or not _m(_SIG, b["release_sig"])
            or raw["signer"] != b["pubkey"]
            or b["release_pubkey"] == b["pubkey"]
        ):
            return None
        proof = founder_bytes(network_id, _release_proof(b["pubkey"], b["release_pubkey"]))
        if not _verify_raw(b["release_pubkey"], proof, b["release_sig"]):
            return None
        if not _verify_raw(raw["signer"], founder_bytes(network_id, _unsigned(raw)), raw["sig"]):
            return None  # proof of possession of the node key
        return Founder(b["id"], b["pubkey"], b["release_pubkey"], b["params_hash"], raw)
    except Exception:  # noqa: BLE001  never raises
        return None


def ceremony_genesis(params: dict, founders: Sequence[Founder]) -> dict:
    """Deterministic: the same founders and network.toml give a byte-identical genesis."""
    n = len(founders)
    f = n // 4
    return {
        "network_id": params["name"],
        "f": f,
        "replicas": n,
        "threshold": f + 1,
        "build_timeout_s": params["build_timeout_s"],
        "request_ttl_s": params["request_ttl_s"],
        "sync_interval_s": params["sync_interval_s"],
        "allowed_repos": list(params["allowed_repos"]),
        "allowed_images": dict(params["allowed_images"]),
        "allowed_goos": list(params["allowed_goos"]),
        "allowed_goarch": list(params["allowed_goarch"]),
        "release_signers": [
            {"id": x.id + "-rel", "pubkey": x.release_pubkey}
            for x in sorted(founders, key=lambda x: x.release_pubkey)
        ],
        "nodes": [
            {"id": x.id, "operator": x.id, "pubkey": x.pubkey}
            for x in sorted(founders, key=lambda x: x.pubkey)
        ],
    }


def seal_problem(params: dict, founders: Sequence[Founder], me_pubkey: str) -> str | None:
    """Why the seal must wait, or None."""
    if len(founders) < 2:
        return f"need at least 2 founders, have {len(founders)}"
    ids = [x.id for x in founders]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        return f"two founders share the name {dup[0]}: rerun one with --name"
    mine = params_hash(params)
    odd = sorted(x.id for x in founders if x.params_hash != mine)
    if odd:
        return f"different network.toml on: {', '.join(odd)}"
    if me_pubkey not in {x.pubkey for x in founders}:
        return "this laptop is not in the list yet"
    try:
        parse_genesis(ceremony_genesis(params, founders))
    except GenesisError as e:
        return f"invalid genesis: {e}"
    return None


def short_code(genesis_hash: str) -> str:
    h = genesis_hash[:16].upper()
    return "-".join(h[i : i + 4] for i in range(0, 16, 4))


@dataclass(frozen=True)
class Endorse:
    signer: str
    genesis_hash: str
    raw: dict


def make_endorse(g: Genesis, me: Node, sk) -> bytes:
    unsigned = {"v": 1, "type": "endorse", "signer": me.id, "body": {"genesis_hash": g.hash}}
    return canonical_json({**unsigned, "sig": sign(sk, g.hash, unsigned)})


def parse_endorse(data: Any, pubkeys: Mapping[str, str]) -> Endorse | None:
    """`pubkeys`: founder id -> node pubkey. Verified with the hash it carries (L42)."""
    try:
        raw, _ = _load(data, MAX_CEREMONY)
        if raw is None or raw["type"] != "endorse" or set(raw["body"]) != {"genesis_hash"}:
            return None
        gh, signer = raw["body"]["genesis_hash"], raw["signer"]
        if not _m(_HEX64, gh) or not isinstance(signer, str) or signer not in pubkeys:
            return None
        if not verify(pubkeys[signer], gh, _unsigned(raw), raw["sig"]):
            return None
        return Endorse(signer, gh, raw)
    except Exception:  # noqa: BLE001  never raises
        return None


@dataclass(frozen=True)
class Seal:
    """A founder's proposal: "seal the network with exactly these founders" (RFC §7.16)."""

    signer: str  # the proposer's node pubkey
    genesis_hash: str  # what the proposer computed from the list below
    founders: tuple[tuple[str, str], ...]  # (name, pubkey), sorted by pubkey
    raw: dict


def make_seal(network_id: str, sk, founders: Sequence[Founder], genesis_hash: str) -> bytes:
    body = {
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "founders": [
            {"id": x.id, "pubkey": x.pubkey} for x in sorted(founders, key=lambda x: x.pubkey)
        ],
    }
    unsigned = {"v": 1, "type": "seal", "signer": pubkey_hex(sk), "body": body}
    sig = sk.sign(founder_bytes(network_id, unsigned)).signature.hex()
    return canonical_json({**unsigned, "sig": sig})


def parse_seal(data: Any, network_id: str) -> Seal | None:
    try:
        raw, _ = _load(data, MAX_SEAL)
        if raw is None or raw["type"] != "seal":
            return None
        b = raw["body"]
        if (
            set(b) != {"network_id", "genesis_hash", "founders"}
            or b["network_id"] != network_id
            or not _m(_HEX64, b["genesis_hash"])
            or not _m(_HEX64, raw["signer"])
            or not isinstance(b["founders"], list)
            or not 1 <= len(b["founders"]) <= MAX_FOUNDERS
        ):
            return None
        entries = b["founders"]
        if any(
            not isinstance(x, dict)
            or set(x) != {"id", "pubkey"}
            or not valid_name(x["id"])
            or not _m(_HEX64, x["pubkey"])
            for x in entries
        ):
            return None
        keys = [x["pubkey"] for x in entries]
        if keys != sorted(set(keys)) or raw["signer"] not in keys:
            return None  # sorted and distinct: one canonical form; the proposer is a founder
        if not _verify_raw(raw["signer"], founder_bytes(network_id, _unsigned(raw)), raw["sig"]):
            return None
        return Seal(
            raw["signer"], b["genesis_hash"], tuple((x["id"], x["pubkey"]) for x in entries), raw
        )
    except Exception:  # noqa: BLE001  never raises
        return None


def check_endorsements(g: Genesis, envs: Iterable[Any]) -> bool:
    """True iff every node of g endorsed g.hash: unanimity, anyone can veto."""
    pubkeys = {n.id: n.pubkey for n in g.nodes}
    ok = set()
    for raw in envs:
        e = parse_endorse(raw, pubkeys)
        if e is not None and e.genesis_hash == g.hash:
            ok.add(e.signer)
    return ok == set(pubkeys)
