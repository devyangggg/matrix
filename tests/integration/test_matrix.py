"""Real eight-process Docker-backed RFC §9.1 fault matrix."""

import asyncio
import os
import time
from hashlib import sha256

import pytest
from harness import IMAGE, REPO, ROOT, Network
from nacl.signing import SigningKey

pytestmark = pytest.mark.integration
TAG = os.environ.get("MATRIX_TEST_TAG", "")
COMMIT = os.environ.get("MATRIX_TEST_COMMIT", "")
PATCH = ROOT / "examples" / "faults" / "backdoor.patch"


@pytest.fixture(autouse=True)
def prerequisites():
    if not all((REPO, IMAGE, TAG, COMMIT)):
        pytest.skip(
            "set MATRIX_TEST_REPO, MATRIX_TEST_IMAGE, MATRIX_TEST_TAG, MATRIX_TEST_COMMIT"
        )


def signed_request(network):
    from matrix.genesis import load_genesis
    from matrix.model import make_envelope, request_id

    g = load_genesis(str(network.directory / "dev" / "genesis.json"))
    seed = bytes.fromhex(
        (network.directory / "dev" / "keys" / "release.key").read_text().strip()
    )
    body = {"v": 1, "repo_url": REPO, "tag": TAG, "commit": COMMIT}
    return (
        request_id(body),
        make_envelope("release", "ci-release", body, SigningKey(seed), g),
        g,
    )


async def collect(network, rid, request, genesis, *, deadline=170):
    from matrix.verdict import verdict

    end = time.monotonic() + deadline
    last = None
    while time.monotonic() < end:
        seen = {}
        for node_id in network.processes:
            bundle = await network.bundle(node_id, rid)
            if bundle:
                for envelope in bundle["envelopes"]:
                    seen[envelope["sig"]] = envelope
        last = verdict(request, seen.values(), genesis)
        if last.state != "PENDING":
            return last
        await asyncio.sleep(1)
    return last


async def release(network):
    rid, request, genesis = signed_request(network)
    # Three independent operators receive the request even if an operator is malicious.
    accepted = []
    for node_id in ("builder1", "builder3", "builder5", "builder7"):
        if node_id not in network.processes:
            continue
        try:
            accepted.append(await network.post(node_id, "/v1/requests", request))
        except (OSError, TimeoutError):
            pass
    assert 202 in accepted
    return rid, request, genesis


async def wait_attest(network, rid, signer, deadline=120):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        bundle = await network.bundle(signer, rid)
        if bundle:
            for envelope in bundle["envelopes"]:
                if envelope["signer"] == signer:
                    return envelope["body"]["result"]
        await asyncio.sleep(1)
    pytest.fail(f"{signer} did not attest")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode", ["inject", "lie", "collude", "stall", "equivocate", "bad-artifact"]
)
@pytest.mark.parametrize(
    "placement", [("builder1",), ("builder1", "builder2"), ("builder1", "builder3")]
)
async def test_faulty_builders_cannot_certify_fake_hash(tmp_path, mode, placement):
    if mode == "inject" and not PATCH.is_file():
        pytest.skip("Track B sample backdoor.patch is not available")
    settings = {
        "inject": ["--fault", "inject", "--patch", str(PATCH)],
        "lie": ["--fault", "lie"],
        "collude": ["--fault", "collude", "--hash", "f" * 64],
        "stall": ["--fault", "stall"],
        "equivocate": ["--fault", "equivocate"],
        "bad-artifact": ["--fault", "bad-artifact"],
    }
    async with Network(
        tmp_path, {node: settings[mode] for node in placement}
    ) as network:
        rid, request, genesis = await release(network)
        result = await collect(network, rid, request, genesis)
        assert result.state == "AGREED"
        assert result.hash != "f" * 64
        if mode in ("inject", "lie", "collude"):
            for signer in placement:
                assert await wait_attest(network, rid, signer) != result.hash
        if mode == "bad-artifact":
            # A quorum can form before this builder has finished; wait for its artifact.
            node = placement[0]
            end = time.monotonic() + 60
            while time.monotonic() < end:
                async with network.session.get(
                    f"http://{network.address(node)}/v1/artifacts/{result.hash}"
                ) as response:
                    if response.status == 200:
                        assert sha256(await response.read()).hexdigest() != result.hash
                        break
                await asyncio.sleep(1)
            else:
                pytest.fail("faulty builder did not serve its built artifact")
        if mode == "equivocate":
            end = time.monotonic() + 15
            proof = False
            while time.monotonic() < end:
                async with network.session.get(
                    f"http://{network.address('builder8')}/v1/evidence"
                ) as response:
                    items = (await response.json())["evidence"]
                    proof = any(
                        item["kind"] == "EQUIVOCATION" and item["proof"]
                        for item in items
                    )
                if proof:
                    break
                await asyncio.sleep(1)
            assert proof


@pytest.mark.asyncio
async def test_crashed_laptop_spends_two_liveness_slots(tmp_path):
    async with Network(tmp_path, offline={"builder7", "builder8"}) as network:
        rid, request, genesis = await release(network)
        assert (await collect(network, rid, request, genesis)).state == "AGREED"


@pytest.mark.asyncio
async def test_crash_mode_exits_and_remaining_builders_certify(tmp_path):
    async with Network(tmp_path, {"builder7": ["--fault", "crash"]}) as network:
        _, request, _ = signed_request(network)
        try:
            await network.post("builder7", "/v1/requests", request)
        except (OSError, TimeoutError):
            pass
        assert await asyncio.wait_for(network.processes["builder7"].wait(), 5) == 1
        assert (await collect(network, *(await release(network)))).state == "AGREED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "crashed,expected",
    [
        (("builder3", "builder4", "builder5"), "AGREED"),
        (("builder3", "builder4", "builder5", "builder6"), "PENDING"),
    ],
)
async def test_two_stalling_malicious_plus_crashed_honest(tmp_path, crashed, expected):
    async with Network(
        tmp_path,
        {"builder1": ["--fault", "stall"], "builder2": ["--fault", "stall"]},
        set(crashed),
    ) as network:
        rid, request, genesis = await release(network)
        result = await collect(
            network,
            rid,
            request,
            genesis,
            deadline=165 if expected == "PENDING" else 170,
        )
        assert result.state == expected
