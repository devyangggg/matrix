"""Signed hellos, the address book and the founding ceremony (RFC rev 5 §7.15, §7.16)."""

import random
import socket

import pytest
from conftest import seed_for
from nacl.signing import SigningKey

from matrix import discovery as d
from matrix.canon import canonical_json, loads_strict
from matrix.genesis import parse_genesis

ADDR = "192.168.43.17:7700"


def hello(genesis, keys, signer="builder2", addr=ADDR, seq=1000, key=None, gh=None):
    g = genesis if gh is None else _with_hash(genesis, gh)
    return d.make_hello(g, genesis.node(signer), key or keys[signer], addr, seq)


def _with_hash(genesis, gh):
    from dataclasses import replace

    return replace(genesis, hash=gh)


# --- hello parsing: every receiver check ------------------------------------------------------


def test_valid_hello_round_trip(genesis, keys):
    h = d.parse_hello(hello(genesis, keys), genesis)
    assert (h.signer, h.addr, h.seq) == ("builder2", ADDR, 1000)
    assert d.parse_hello(loads_strict(hello(genesis, keys)), genesis) is not None  # dict input


def test_reasons_in_check_order(genesis, keys):
    def reason(data, last=None):
        return d._check_hello(data, genesis, last)[1]

    assert reason(b" " * (d.MAX_HELLO + 1)) == "size"
    assert reason(b"not json") == "parse"
    stranger = SigningKey(b"\x05" * 32)
    raw = loads_strict(hello(genesis, keys))
    raw["signer"] = "mallory"
    assert reason(canonical_json(raw)) == "signer"  # stranger: dropped before signature work
    assert reason(hello(genesis, keys, gh="e" * 64)) == "genesis"  # another network
    assert reason(hello(genesis, keys, seq=5), {"builder2": 5}) == "replay"
    assert reason(hello(genesis, keys, key=stranger)) == "sig"  # forged: wrong key
    assert reason(hello(genesis, keys, key=keys["builder3"])) == "sig"  # another member's key


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(type="founder"),
        lambda r: r.update(v=True),
        lambda r: r.update(extra=1),
        lambda r: r["body"].update(extra=1),
        lambda r: r["body"].update(seq=-1),
        lambda r: r["body"].update(seq=True),
        lambda r: r["body"].update(seq="1"),
        lambda r: r["body"].update(addr="192.168.43.17"),
        lambda r: r["body"].update(addr="256.1.1.1:7700"),
        lambda r: r["body"].update(addr="10.0.0.1:0"),
        lambda r: r["body"].update(addr="10.0.0.1:70000"),
        lambda r: r["body"].update(addr="evil.example:7700"),
        lambda r: r["body"].update(addr="[::1]:7700"),
        lambda r: r.update(sig="0" * 127),
        lambda r: r.update(body=[]),
    ],
)
def test_malformed_hellos_are_dropped(genesis, keys, mutate):
    raw = loads_strict(hello(genesis, keys))
    mutate(raw)
    assert d.parse_hello(raw, genesis) is None


def test_tampered_address_fails_the_signature(genesis, keys):
    raw = loads_strict(hello(genesis, keys))
    raw["body"]["addr"] = "10.0.0.66:7700"  # redirect attempt
    assert d._check_hello(raw, genesis, None)[1] == "sig"


def test_parse_never_raises(genesis, keys):
    good = hello(genesis, keys)
    rng = random.Random(7)
    for _ in range(2000):
        b = bytearray(good)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        assert d.parse_hello(bytes(b), genesis) is None or bytes(b) == good
    for junk in (None, 3, "x", [], {"v": 1.5}, b"\xff" * 10, {"sig": float("nan")}):
        assert d.parse_hello(junk, genesis) is None


# --- address book -----------------------------------------------------------------------------


def test_book_learns_and_tracks_changes(genesis, keys, clock):
    book = d.AddressBook(genesis, clock)
    assert book.accept(hello(genesis, keys, seq=1)) is not None
    assert book.addr("builder2") == ADDR and book.online("builder2", clock())
    assert book.accept(hello(genesis, keys, seq=1)) is None  # replay
    h = d.parse_hello(hello(genesis, keys, addr="192.168.43.99:7700", seq=2), genesis)
    assert book.update(h) is True  # DHCP gave it a new IP
    h3 = d.parse_hello(hello(genesis, keys, addr="192.168.43.99:7700", seq=3), genesis)
    assert book.update(h3) is False  # same address
    assert book.update(h) is False  # older seq never overwrites
    assert book.addr("builder2") == "192.168.43.99:7700"


def test_book_online_window_and_membership(genesis, keys, clock):
    book = d.AddressBook(genesis, clock)
    book.accept(hello(genesis, keys))
    clock.advance(d.ONLINE_WINDOW_S - 1)
    assert book.online("builder2", clock())
    clock.advance(1)
    assert not book.online("builder2", clock())  # offline, yet still a member: disconnect != leave
    assert book.addr("builder2") == ADDR
    stranger = SigningKey(b"\x05" * 32)
    raw = loads_strict(d.make_hello(genesis, genesis.node("builder3"), stranger, ADDR, 9))
    assert book.accept(raw) is None and book.addr("builder3") is None


def test_book_hellos_sorted_latest_only(genesis, keys, clock):
    book = d.AddressBook(genesis, clock)
    for signer, seq in [("builder3", 1), ("builder2", 1), ("builder2", 2)]:
        book.accept(hello(genesis, keys, signer=signer, seq=seq))
    assert [(h["signer"], h["body"]["seq"]) for h in book.hellos()] == [
        ("builder2", 2),
        ("builder3", 1),
    ]


# --- Discovery behaviour without real broadcasts -----------------------------------------------


class FakeTransport:
    def __init__(self):
        self.sent: list[tuple[bytes, tuple]] = []

    def sendto(self, data, dest):
        self.sent.append((data, dest))


def make_discovery(genesis, keys, clock, me="builder1"):
    book = d.AddressBook(genesis, clock)
    disc = d.Discovery(genesis, genesis.node(me), keys[me], book, 7700, "192.168.43.10:7700")
    disc.clock = clock
    disc.transport = FakeTransport()
    disc.addr = "192.168.43.10:7700"
    return disc, book


def test_announce_broadcasts_and_lists_itself(genesis, keys, clock):
    disc, book = make_discovery(genesis, keys, clock)
    disc.announce()
    disc.announce()  # same clock: seq still increases, or receivers would drop it
    (a, dest_a), (b, dest_b) = disc.transport.sent
    assert dest_a == dest_b == (d.BROADCAST, d.DISCOVERY_PORT)
    assert loads_strict(b)["body"]["seq"] == loads_strict(a)["body"]["seq"] + 1
    assert book.addr("builder1") == "192.168.43.10:7700"  # /v1/peers lists this node too
    other = d.AddressBook(genesis, clock)
    assert other.accept(a) is not None and other.accept(b) is not None


def test_new_peer_gets_a_unicast_reply_once(genesis, keys, clock):
    disc, book = make_discovery(genesis, keys, clock)
    disc.announce()
    disc.transport.sent.clear()
    disc.on_datagram(hello(genesis, keys, seq=1), ("192.168.43.17", 7788))
    assert disc.transport.sent == [(disc.last, ("192.168.43.17", d.DISCOVERY_PORT))]
    disc.on_datagram(hello(genesis, keys, seq=2), ("192.168.43.17", 7788))  # same address
    assert len(disc.transport.sent) == 1
    assert book.addr("builder2") == ADDR


def test_own_echo_and_garbage_are_ignored(genesis, keys, clock):
    disc, book = make_discovery(genesis, keys, clock)
    disc.announce()
    echo = disc.transport.sent[0][0]
    disc.transport.sent.clear()
    disc.on_datagram(echo, ("192.168.43.10", 7788))
    disc.on_datagram(b"\x00garbage", ("10.0.0.9", 7788))
    disc.on_datagram(hello(genesis, keys, key=SigningKey(b"\x05" * 32)), ("10.0.0.9", 7788))
    assert disc.transport.sent == [] and set(book.seqs) == {"builder1"}


def test_send_only_socket_needs_no_bind():
    s = d.udp_socket(None)
    try:
        assert s.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST)
    finally:
        s.close()


def test_valid_addr():
    assert d.valid_addr("172.20.10.3:7700") and d.valid_addr("0.0.0.0:1")
    for bad in ("1.2.3:7", "1.2.3.4", "1.2.3.4:65536", "300.1.1.1:1", 5, None, "a.b.c.d:1"):
        assert not d.valid_addr(bad)


# --- founding ceremony ------------------------------------------------------------------------

PARAMS = {
    "name": "matrix-demo",
    "allowed_repos": ["https://github.com/org/hello"],
    "allowed_images": {"go1.23": "golang@sha256:" + "a" * 64},
    "allowed_goos": ["linux"],
    "allowed_goarch": ["amd64"],
    "build_timeout_s": 45,
    "request_ttl_s": 3600,
    "sync_interval_s": 5,
}
NAMES = ["laptop-a", "laptop-b", "laptop-c", "laptop-d", "laptop-e", "laptop-f", "laptop-g"]


def node_key(name):
    return SigningKey(seed_for(name))


def release_key(name):
    return SigningKey(seed_for(name + "-rel"))


def founder(name, params=PARAMS):
    return d.make_founder(params, name, node_key(name), release_key(name))


def founders(n=4):
    return [d.parse_founder(founder(x), PARAMS["name"]) for x in NAMES[:n]]


def test_network_toml(tmp_path):
    p = tmp_path / "network.toml"
    p.write_text(
        '[network]\nname = "matrix-demo"\nallowed_repos = ["https://github.com/org/hello"]\n'
        'allowed_images = { "go1.23" = "golang@sha256:' + "a" * 64 + '" }\n'
        'allowed_goos = ["linux"]\nallowed_goarch = ["amd64"]\n'
        "build_timeout_s = 45\nrequest_ttl_s = 3600\nsync_interval_s = 5\n"
    )
    assert d.load_network(str(p)) == PARAMS
    for bad in ("", "[network]\nname = 'x'\n", p.read_text().replace("45", "45.0")):
        p.write_text(bad)
        with pytest.raises(d.NetworkError):
            d.load_network(str(p))
    with pytest.raises(d.NetworkError):
        d.load_network(str(tmp_path / "missing.toml"))


def test_repo_network_toml_is_valid():
    params = d.load_network("network.toml")  # tests run from the repo root
    assert params["name"] and params["build_timeout_s"] < params["request_ttl_s"]


def test_default_name(monkeypatch):
    monkeypatch.setattr(d.socket, "gethostname", lambda: "Dhruv's MacBook.local-" + "x" * 40)
    name = d.default_name()
    assert name == "dhruv-s-macbook-local-xx" and d.valid_name(name)


def test_founder_round_trip_and_rejections():
    f = d.parse_founder(founder("laptop-a"), "matrix-demo")
    assert f.id == "laptop-a" and f.pubkey == node_key("laptop-a").verify_key.encode().hex()
    assert f.params_hash == d.params_hash(PARAMS)
    assert d.parse_founder(founder("laptop-a"), "other-network") is None
    raw = loads_strict(founder("laptop-a"))
    raw["body"]["id"] = "laptop-z"  # tampered after signing
    assert d.parse_founder(canonical_json(raw), "matrix-demo") is None
    raw = loads_strict(founder("laptop-a"))
    raw["body"]["release_pubkey"] = release_key("laptop-b").verify_key.encode().hex()
    assert d.parse_founder(canonical_json(raw), "matrix-demo") is None  # claims b's release key


def test_founder_cannot_claim_someone_elses_release_key():
    # signed correctly with a's node key, but the release proof is not made by that release key
    nid, a, b_rel = "matrix-demo", node_key("laptop-a"), release_key("laptop-b")
    pub, rpub = a.verify_key.encode().hex(), b_rel.verify_key.encode().hex()
    forged_proof = release_key("laptop-a").sign(d.founder_bytes(nid, d._release_proof(pub, rpub)))
    body = {
        "network_id": nid,
        "id": "laptop-a",
        "pubkey": pub,
        "release_pubkey": rpub,
        "release_sig": forged_proof.signature.hex(),
        "params_hash": d.params_hash(PARAMS),
    }
    unsigned = {"v": 1, "type": "founder", "signer": pub, "body": body}
    sig = a.sign(d.founder_bytes(nid, unsigned)).signature.hex()
    assert d.parse_founder(canonical_json({**unsigned, "sig": sig}), nid) is None


def test_founder_signature_cannot_be_replayed_as_an_envelope(genesis):
    from matrix.model import parse_envelope

    assert parse_envelope(loads_strict(founder("laptop-a")), genesis) is None


def test_seal_problems():
    fs = founders(4)
    me = fs[0].pubkey
    assert d.seal_problem(PARAMS, fs[:3], me).startswith("need at least 4")
    dup = d.parse_founder(
        d.make_founder(PARAMS, "laptop-a", node_key("x"), release_key("x")), "matrix-demo"
    )
    assert "laptop-a" in d.seal_problem(PARAMS, [*fs, dup], me)
    other = d.parse_founder(founder("laptop-e", {**PARAMS, "build_timeout_s": 46}), "matrix-demo")
    assert "laptop-e" in d.seal_problem(PARAMS, [*fs, other], me)
    assert d.seal_problem(PARAMS, fs, "f" * 64) == "this laptop is not in the list yet"
    assert d.seal_problem(PARAMS, fs, me) is None


def test_ceremony_genesis_is_deterministic_and_valid():
    fs = founders(4)
    a = d.ceremony_genesis(PARAMS, fs)
    b = d.ceremony_genesis(PARAMS, list(reversed(fs)))
    assert canonical_json(a) == canonical_json(b)  # same founders => same hash on every laptop
    g = parse_genesis(a)
    assert (g.f, g.replicas, g.threshold, len(g.nodes)) == (1, 4, 2, 4)
    assert all(n.addr is None and n.operator == n.id for n in g.nodes)
    assert sorted(s.id for s in g.release_signers) == [x + "-rel" for x in NAMES[:4]]
    g7 = parse_genesis(d.ceremony_genesis(PARAMS, founders(7)))
    assert (g7.f, g7.threshold) == (1, 2)


def test_short_code():
    assert d.short_code("3f2a9c1d77e041b8" + "0" * 48) == "3F2A-9C1D-77E0-41B8"


def _genesis_and_endorsements(n=4):
    fs = founders(n)
    g = parse_genesis(d.ceremony_genesis(PARAMS, fs))
    ends = [loads_strict(d.make_endorse(g, g.node(x), node_key(x))) for x in NAMES[:n]]
    return g, ends


def test_unanimous_endorsement():
    g, ends = _genesis_and_endorsements()
    assert d.check_endorsements(g, ends)
    assert not d.check_endorsements(g, ends[:3])  # anyone can veto by not endorsing
    assert not d.check_endorsements(g, ends[:3] + ends[:1])


def test_endorsements_for_another_genesis_or_forged_do_not_count():
    g, ends = _genesis_and_endorsements()
    other = parse_genesis({**d.ceremony_genesis(PARAMS, founders(4)), "sync_interval_s": 6})
    wrong = loads_strict(d.make_endorse(other, other.node("laptop-d"), node_key("laptop-d")))
    assert not d.check_endorsements(g, ends[:3] + [wrong])
    forged = loads_strict(d.make_endorse(g, g.node("laptop-d"), node_key("laptop-a")))
    assert not d.check_endorsements(g, ends[:3] + [forged])
    pubkeys = {n.id: n.pubkey for n in g.nodes}
    assert d.parse_endorse(canonical_json(wrong), pubkeys).genesis_hash == other.hash
    assert d.parse_endorse(b"garbage", pubkeys) is None
    assert d.parse_endorse(canonical_json(ends[0]), {}) is None
