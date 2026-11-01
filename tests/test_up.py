"""`matrix up`: the founding ceremony over an in-memory bus, and the up command (RFC rev 5 §7.16)."""

import asyncio
import os
import stat

import pytest
from conftest import seed_for
from nacl.signing import SigningKey

from matrix import cli
from matrix import discovery as d
from matrix.canon import canonical_json, loads_strict
from matrix.crypto import pubkey_hex
from matrix.genesis import parse_genesis

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
NAMES = ["laptop-a", "laptop-b", "laptop-c", "laptop-d"]
DOCKER_READY = cli._docker_ready  # the real one; the `home` fixture replaces it with a fake
TOML = (
    '[network]\nname = "matrix-demo"\nallowed_repos = ["https://github.com/org/hello"]\n'
    'allowed_images = { "go1.23" = "golang@sha256:' + "a" * 64 + '" }\n'
    'allowed_goos = ["linux"]\nallowed_goarch = ["amd64"]\n'
    "build_timeout_s = 45\nrequest_ttl_s = 3600\nsync_interval_s = 5\n"
)


def node_key(name):
    return SigningKey(seed_for(name))


def release_key(name):
    return SigningKey(seed_for(name + "-rel"))


class Hub:
    """An in-memory hotspot: every send reaches every open bus, like a UDP broadcast."""

    def __init__(self):
        self.buses = []
        self.extra: dict[int, list[bytes]] = {}  # bus index -> datagrams only it receives
        self.drop_seals = 0  # lose the next N seal proposals on the wire


class MemBus:
    def __init__(self, hub: Hub, index: int):
        self.hub, self.index, self.cb = hub, index, None

    async def open(self, cb):
        self.cb = cb
        self.hub.buses.append(self)
        for data in self.hub.extra.get(self.index, []):
            cb(data, ("10.0.0.66", d.DISCOVERY_PORT))

    def send(self, data):
        if self.hub.drop_seals and b'"type":"seal"' in data:
            self.hub.drop_seals -= 1
            return
        loop = asyncio.get_running_loop()
        for b in list(self.hub.buses):
            loop.call_soon(b.cb, data, ("10.0.0.1", d.DISCOVERY_PORT))

    def close(self):
        self.hub.buses.remove(self)


def answers(confirm="y"):
    refused = False

    async def ask(kind):
        nonlocal refused
        await asyncio.sleep(0.02)
        if refused:
            return ""  # the user closed the terminal after refusing
        if kind == "confirm":
            refused = confirm != "y"
            return f"{confirm}\n"
        return "\n"

    return ask


def accepts():
    """A laptop whose user never proposes: `y` at every prompt accepts a proposal once one shows."""

    async def ask(kind):
        await asyncio.sleep(0.02)
        return "y\n"

    return ask


async def found(hub, confirms=("y", "y", "y", "y"), timeout=5.0):
    return await asyncio.gather(
        *(
            cli.ceremony(
                PARAMS,
                name,
                node_key(name),
                release_key(name),
                MemBus(hub, i),
                answers(confirms[i]),
                timeout=timeout,
                interval=0.01,
            )
            for i, name in enumerate(NAMES)
        )
    )


# --- the ceremony ---------------------------------------------------------------------------


async def test_four_laptops_found_the_same_network(capsys):
    results = await found(Hub())
    assert all(r is not None for r in results)
    raws = {canonical_json(r[0]) for r in results}
    assert len(raws) == 1  # byte-identical genesis on every laptop
    g = parse_genesis(results[0][0])
    assert (g.f, g.replicas, g.threshold, len(g.nodes)) == (1, 4, 2, 4)
    assert all(n.addr is None for n in g.nodes)
    for raw, endorsements, own in results:
        assert d.check_endorsements(g, endorsements)  # unanimity
        assert [e["signer"] for e in endorsements] == sorted(NAMES)
        assert loads_strict(own) in endorsements
    out = capsys.readouterr().out
    assert f"Short code: {d.short_code(g.hash)}" in out


@pytest.mark.parametrize("lost", [0, 5])  # lost seals are re-sent every round
async def test_other_laptops_accept_one_proposal(lost):
    hub = Hub()
    hub.drop_seals = lost
    asks = [answers(), accepts(), accepts(), accepts()]  # only laptop-a presses Enter
    results = await asyncio.gather(
        *(
            cli.ceremony(
                PARAMS,
                name,
                node_key(name),
                release_key(name),
                MemBus(hub, i),
                asks[i],
                timeout=5.0,
                interval=0.01,
            )
            for i, name in enumerate(NAMES)
        )
    )
    assert all(r is not None for r in results)
    assert len({canonical_json(r[0]) for r in results}) == 1


async def test_proposal_that_arrives_before_its_founder_waits_then_shows(capsys):
    # Out of order: laptop-x's seal reaches laptop-a before laptop-x's own announcement.
    def founder(name, key):
        return d.parse_founder(
            d.make_founder(PARAMS, name, node_key(key), release_key(key)), "matrix-demo"
        )

    fa, fx = founder("laptop-a", "laptop-a"), founder("laptop-x", "x")
    g = parse_genesis(d.ceremony_genesis(PARAMS, [fa, fx]))
    hub = Hub()
    hub.extra[0] = [
        d.make_seal("matrix-demo", node_key("x"), [fa, fx], g.hash),
        canonical_json(fx.raw),
    ]
    await cli.ceremony(
        PARAMS,
        "laptop-a",
        node_key("laptop-a"),
        release_key("laptop-a"),
        MemBus(hub, 0),
        accepts(),
        timeout=0.3,
        interval=0.01,
    )
    out = capsys.readouterr().out
    assert out.index("not heard yet: laptop-x") < out.index("Same list as yours")
    assert "Accepted the proposal with 2 founders" in out


async def test_anyone_can_veto():
    results = await found(Hub(), confirms=("y", "y", "y", "n"), timeout=0.5)
    assert results == [None, None, None, None]  # laptop-d said no: nobody founds anything


async def test_rogue_seen_by_one_laptop_aborts_everyone(capsys):
    # A fifth device reaches only laptop-d (e.g. it sat closer to it). laptop-d's genesis has five
    # members and a different short code; the endorsements conflict and every laptop aborts.
    hub = Hub()
    hub.extra[3] = [d.make_founder(PARAMS, "rogue", node_key("rogue"), release_key("rogue"))]
    results = await found(hub, timeout=2.0)
    assert results == [None, None, None, None]
    assert "sealed a different genesis" in capsys.readouterr().err


async def test_two_laptops_found_a_network_without_fault_tolerance(capsys):
    hub = Hub()
    results = await asyncio.gather(
        *(
            cli.ceremony(
                PARAMS,
                name,
                node_key(name),
                release_key(name),
                MemBus(hub, i),
                answers(),
                timeout=5.0,
                interval=0.01,
            )
            for i, name in enumerate(NAMES[:2])
        )
    )
    assert all(r is not None for r in results)
    g = parse_genesis(results[0][0])
    assert (g.f, g.replicas, g.threshold, len(g.nodes)) == (0, 2, 1, 2)
    assert "WARNING: 2 founders give f=0" in capsys.readouterr().out


async def test_one_key_under_two_names_blocks_the_seal(capsys):
    # A stale `matrix up --name old` and a new one on the same laptop: "latest wins" would flip,
    # so laptops sealing at different moments would disagree on the genesis.
    hub = Hub()
    hub.extra[0] = [
        d.make_founder(PARAMS, name, node_key("x"), release_key("x")) for name in ("old", "new")
    ]
    task = asyncio.create_task(
        cli.ceremony(
            PARAMS,
            "laptop-a",
            node_key("laptop-a"),
            release_key("laptop-a"),
            MemBus(hub, 0),
            answers(),
            timeout=0.5,
            interval=0.01,
        )
    )
    await asyncio.sleep(0.2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    out = capsys.readouterr().out
    assert "announces as new and old" in out and "cannot seal yet: key" in out


async def test_seal_waits_for_matching_network_toml(capsys):
    hub = Hub()
    other = {**PARAMS, "build_timeout_s": 46}
    hub.extra[0] = [d.make_founder(other, "laptop-x", node_key("x"), release_key("x"))]
    task = asyncio.create_task(
        cli.ceremony(
            PARAMS,
            "laptop-a",
            node_key("laptop-a"),
            release_key("laptop-a"),
            MemBus(hub, 0),
            answers(),
            timeout=0.5,
            interval=0.01,
        )
    )
    await asyncio.sleep(0.2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    out = capsys.readouterr().out
    assert (
        "params MISMATCH" in out and "cannot seal yet: different network.toml on: laptop-x" in out
    )
    assert hub.buses == []  # the bus is closed even when cancelled


async def test_placeholder_network_toml_is_refused_at_seal(capsys):
    placeholder = {**PARAMS, "allowed_repos": ["https://github.com/<org>/matrix-hello"]}
    hub = Hub()
    results = await asyncio.wait_for(
        asyncio.gather(
            *(
                asyncio.wait_for(
                    cli.ceremony(
                        placeholder,
                        n,
                        node_key(n),
                        release_key(n),
                        MemBus(hub, i),
                        answers(),
                        interval=0.01,
                    ),
                    0.5,
                )
                for i, n in enumerate(NAMES)
            ),
            return_exceptions=True,
        ),
        2,
    )
    assert all(isinstance(r, TimeoutError) for r in results)
    assert "invalid genesis" in capsys.readouterr().out


# --- the up command -------------------------------------------------------------------------


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A laptop: repo checkout with network.toml as cwd, ~/.matrix in tmp, no real node/UDP."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "network.toml").write_text(TOML)
    monkeypatch.chdir(repo)
    h = tmp_path / "home"
    calls = []

    async def fake_run(args):
        await asyncio.sleep(0.01)  # a real builder runs for hours: background tasks get to start
        calls.append(args)

    async def no_broadcast(data, seconds):
        calls.append(("endorse", data))

    async def docker_ok(images):
        return True

    monkeypatch.setattr(cli.node, "run", fake_run)
    monkeypatch.setattr(cli, "_keep_endorsing", no_broadcast)
    monkeypatch.setattr(cli, "_docker_ready", docker_ok)
    return h, calls


def _keys(h, name="laptop-a"):
    keys = h / "keys"
    keys.mkdir(parents=True)
    cli._write_key(keys / "node.key", seed_for(name).hex())
    cli._write_key(keys / "release.key", seed_for(name + "-rel").hex())


async def _result():
    return (await found(Hub()))[0]


def test_up_founds_writes_files_and_starts_the_node(home, monkeypatch):
    h, calls = home
    _keys(h)
    result = asyncio.run(_result())
    seen = []

    async def fake_ceremony(params, name, sk, rsk, bus, ask, **kw):
        seen.append((params, name, pubkey_hex(sk), pubkey_hex(rsk)))
        return result

    monkeypatch.setattr(cli, "ceremony", fake_ceremony)
    assert cli.run(["up", "--home", str(h), "--name", "laptop-a"]) == 0
    assert seen == [(PARAMS, "laptop-a", pubkey_hex(node_key("laptop-a")), seen[0][3])]
    g = parse_genesis(loads_strict((h / "genesis.json").read_bytes()))
    assert (h / "genesis.sha256").read_text() == g.hash + "\n"
    assert d.check_endorsements(g, loads_strict((h / "endorsements.json").read_bytes()))
    run_args = calls[-1]
    assert (run_args.id, run_args.listen, run_args.no_discovery) == (
        "laptop-a",
        "0.0.0.0:7700",
        False,
    )
    assert run_args.data == str(h / "data") and run_args.key == str(h / "keys" / "node.key")
    assert calls[0][0] == "endorse"  # keeps endorsing for laptops that confirm later


def test_up_creates_private_keys_on_first_run(home, monkeypatch):
    h, _ = home

    async def abort(*a, **kw):
        return None

    monkeypatch.setattr(cli, "ceremony", abort)
    assert cli.run(["up", "--home", str(h), "--name", "laptop-a"]) == 4
    for k in ("node.key", "release.key"):
        assert (h / "keys" / k).exists()
        if os.name == "posix":
            assert stat.S_IMODE((h / "keys" / k).stat().st_mode) == 0o600
    assert not (h / "genesis.json").exists()  # an aborted ceremony writes nothing


def test_up_skips_the_ceremony_once_founded(home, monkeypatch):
    h, calls = home
    _keys(h)
    raw, endorsements, _ = asyncio.run(_result())
    g = parse_genesis(raw)
    (h / "genesis.json").write_bytes(canonical_json(raw))
    (h / "genesis.sha256").write_text(g.hash + "\n")
    (h / "endorsements.json").write_bytes(canonical_json(endorsements))

    async def must_not_run(*a, **kw):
        raise AssertionError("ceremony ran again")

    monkeypatch.setattr(cli, "ceremony", must_not_run)
    assert cli.run(["up", "--home", str(h)]) == 0
    assert calls[-1].id == "laptop-a" and all(c[0] != "endorse" for c in calls[:-1])


@pytest.mark.parametrize("tamper", ["pin", "endorsement", "genesis"])
def test_up_refuses_a_tampered_network(home, tamper):
    h, calls = home
    _keys(h)
    raw, endorsements, _ = asyncio.run(_result())
    g = parse_genesis(raw)
    pin = g.hash
    if tamper == "pin":
        pin = "0" * 64
    if tamper == "endorsement":
        endorsements = endorsements[:3]
    if tamper == "genesis":
        raw = {**raw, "sync_interval_s": 6}  # hash no longer matches the pin
    (h / "genesis.json").write_bytes(canonical_json(raw))
    (h / "genesis.sha256").write_text(pin + "\n")
    (h / "endorsements.json").write_bytes(canonical_json(endorsements))
    assert cli.run(["up", "--home", str(h)]) == 4
    assert calls == []


def test_up_refuses_a_key_that_is_not_in_genesis(home, monkeypatch):
    h, calls = home
    _keys(h, name="stranger")
    result = asyncio.run(_result())

    async def fake_ceremony(*a, **kw):
        return result

    monkeypatch.setattr(cli, "ceremony", fake_ceremony)
    assert cli.run(["up", "--home", str(h), "--name", "laptop-a"]) == 4
    assert [c for c in calls if not isinstance(c, tuple)] == []


def test_refound_archives_the_old_network(home, monkeypatch):
    h, _ = home
    _keys(h)
    result = asyncio.run(_result())
    (h / "genesis.json").write_bytes(canonical_json(result[0]))
    (h / "genesis.sha256").write_text("old\n")
    (h / "data").mkdir()
    (h / "data" / "matrix.db").write_text("old releases")

    async def fake_ceremony(*a, **kw):
        return result

    monkeypatch.setattr(cli, "ceremony", fake_ceremony)
    assert cli.run(["up", "--home", str(h), "--refound", "--name", "laptop-a"]) == 0
    code = d.short_code(parse_genesis(result[0]).hash)
    old = h / f"old-{code}"
    assert (old / "data" / "matrix.db").read_text() == "old releases"  # nothing deleted
    assert not (h / "data").exists() and (h / "genesis.json").exists()


@pytest.mark.parametrize(
    "argv, message",
    [
        (["--fault", "lie"], "require --allow-faults"),
        (["--name", "bad name!"], "--name must match"),
        (["--advertise", "laptop:7700"], "--advertise must be"),
    ],
)
def test_up_rejects_bad_flags_before_anything(home, capsys, argv, message):
    h, calls = home
    assert cli.run(["up", "--home", str(h), *argv]) == 4
    assert message in capsys.readouterr().err and calls == [] and not h.exists()


def test_up_needs_network_toml(home, monkeypatch, tmp_path, capsys):
    h, _ = home
    monkeypatch.chdir(tmp_path)
    assert cli.run(["up", "--home", str(h), "--name", "laptop-a"]) == 4
    assert "network.toml" in capsys.readouterr().err


def test_up_checks_docker_before_the_ceremony(home, monkeypatch):
    h, calls = home

    async def docker_down(images):
        return False

    async def must_not_run(*args, **kw):
        raise AssertionError("ceremony must not start without Docker")

    monkeypatch.setattr(cli, "_docker_ready", docker_down)
    monkeypatch.setattr(cli, "ceremony", must_not_run)
    assert cli.run(["up", "--home", str(h), "--name", "laptop-a"]) == 4
    assert calls == [] and not h.exists()  # no keys, no files: run again once Docker is up


class FakeDocker:
    """Stands in for asyncio.create_subprocess_exec; records argv, exits per `codes`."""

    def __init__(self, codes=None, missing=False):
        self.codes, self.missing, self.argv = codes or {}, missing, []

    async def __call__(self, *argv, **kw):
        if self.missing:
            raise FileNotFoundError("docker")
        self.argv.append(argv)
        code = self.codes.get(argv[1], 0)

        class Proc:
            async def wait(self):
                return code

        return Proc()


IMAGE = "golang@sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _fixed_isolation(monkeypatch):
    async def gvisor():
        return "runsc", "gVisor (runsc): builds run on a user-space kernel"

    monkeypatch.setattr(cli, "isolation", gvisor)


async def test_docker_ready_pulls_a_missing_image_once(monkeypatch, capsys):
    fake = FakeDocker(codes={"image": 1})  # `docker image inspect` fails: not present
    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", fake)
    assert await DOCKER_READY([IMAGE, IMAGE])
    assert fake.argv == [
        ("docker", "version"),
        ("docker", "image", "inspect", IMAGE),
        ("docker", "pull", "--platform", "linux/amd64", IMAGE),
    ]
    out = capsys.readouterr().out
    assert "pulling the pinned Go toolchain" in out and "build isolation: gVisor" in out


async def test_docker_ready_skips_a_present_image(monkeypatch):
    fake = FakeDocker()
    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", fake)
    assert await DOCKER_READY([IMAGE])
    assert [a[1] for a in fake.argv] == ["version", "image"]


@pytest.mark.parametrize(
    "fake, message",
    [
        (FakeDocker(missing=True), "docker not found"),
        (FakeDocker(codes={"version": 1}), "cannot reach Docker"),
        (FakeDocker(codes={"image": 1, "pull": 1}), "docker pull"),
    ],
)
async def test_docker_ready_explains_what_is_wrong(monkeypatch, capsys, fake, message):
    monkeypatch.setattr(cli.asyncio, "create_subprocess_exec", fake)
    assert not await DOCKER_READY([IMAGE])
    assert message in capsys.readouterr().err


def _double_enter(queue: asyncio.Queue):
    """laptop-a's user presses Enter twice to seal: one stale line stays queued, like the real
    stdin reader. At the y/N prompt they type `y` only if nothing stale answered first."""

    async def ask(kind):
        if kind == "seal":
            await asyncio.sleep(0.02)
            queue.put_nowait("\n")  # the second press
            return "\n"
        if queue.empty():
            queue.put_nowait("y\n")
        return await queue.get()

    return ask


async def _found_with_double_enter(drain_a: bool):
    hub, q = Hub(), asyncio.Queue()

    def drain():
        while not q.empty():
            q.get_nowait()

    tasks = []
    for i, name in enumerate(NAMES):
        ask = _double_enter(q) if i == 0 else answers()
        extra = {"drain": drain} if (i == 0 and drain_a) else {}
        tasks.append(
            cli.ceremony(
                PARAMS, name, node_key(name), release_key(name), MemBus(hub, i), ask,
                timeout=1.0, interval=0.01, **extra,
            )
        )  # fmt: skip
    return await asyncio.gather(*tasks)


async def test_extra_enter_does_not_answer_the_confirmation():
    results = await _found_with_double_enter(drain_a=True)
    assert all(r is not None for r in results)


async def test_without_drain_a_stale_enter_aborts_the_ceremony():
    # the bug the drain fixes: the stale "\n" answered y/N, laptop-a aborted, the others waited
    results = await _found_with_double_enter(drain_a=False)
    assert results == [None, None, None, None]
