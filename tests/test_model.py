import json
from copy import deepcopy
from pathlib import Path

import pytest

from matrix.canon import canonical_json, sha256_hex
from matrix.genesis import parse_genesis
from matrix.model import (
    SIG_PREFIX,
    make_envelope,
    parse_certificate,
    parse_envelope,
    parse_recipe,
    request_id,
    valid_ldflags,
    valid_request,
)

REPO = "https://github.com/org/hello"
GOOD_BODY = {"v": 1, "repo_url": REPO, "commit": "1" * 40, "tag": "v1.2.0"}
RECIPE = """\
[build]
image   = "go1.23"
package = "./cmd/hello"
goos    = "linux"
goarch  = "amd64"
ldflags = "-s -w -buildid= -X main.version=v1.2.0"
output  = "hello"
"""


def test_sig_prefix_reexport():
    assert SIG_PREFIX == b"matrix/v1\0"


def test_request_id_vector():
    v = json.loads((Path(__file__).parent / "vectors" / "request.json").read_text())
    assert request_id(v["body"]) == v["request_id"]


# --- request -------------------------------------------------------------------------------


def test_valid_request_accepts_good(genesis):
    assert valid_request(GOOD_BODY, genesis)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(extra=1),
        lambda b: b.pop("tag"),
        lambda b: b.update(v=2),
        lambda b: b.update(v=True),
        lambda b: b.update(repo_url="https://github.com/org/other"),
        lambda b: b.update(repo_url=["x"]),
        lambda b: b.update(commit="A" * 40),
        lambda b: b.update(commit="1" * 39),
        lambda b: b.update(commit="1" * 41),
        lambda b: b.update(tag=""),
        lambda b: b.update(tag="x" * 65),
        lambda b: b.update(tag="v1/2"),
        lambda b: b.update(tag="v 1"),
        lambda b: b.update(tag="v1\n"),
        lambda b: b.update(tag=5),
    ],
)
def test_valid_request_rejects(genesis, mutate):
    body = deepcopy(GOOD_BODY)
    mutate(body)
    assert not valid_request(body, genesis)


@pytest.mark.parametrize("body", [None, [], "x", 5, {}])
def test_valid_request_rejects_non_dicts(genesis, body):
    assert not valid_request(body, genesis)


# --- ldflags -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "s",
    [
        "",
        "-s",
        "-s -w -buildid=",
        "-s -w -buildid= -X main.version=v1.2.0",
        "-X github.com/acme/hello/internal.Version=",
        "-X main.v=a/b:c@d+e-f_g.h",
    ],
)
def test_ldflags_accepts(s):
    assert valid_ldflags(s)


@pytest.mark.parametrize(
    "s",
    [
        "-extld=gcc",
        "-linkmode=external",
        "-extldflags=-static",
        "-s  -w",
        " -s",
        "-s ",
        "-X",
        "-X main.version",
        "-X main.v=a b",
        "-X main.v=$(id)",
        "-X main.v=a;b",
        "-X main.1v=x",
        "-X -s",
        "-X main.v=" + "a" * 129,
        "-s " * 200,
        "-w;",
        5,
        None,
    ],
)
def test_ldflags_rejects(s):
    assert not valid_ldflags(s)


# --- recipe --------------------------------------------------------------------------------


def test_parse_recipe_accepts_good(genesis):
    r = parse_recipe(RECIPE.encode(), genesis)
    assert r is not None
    assert (r.image, r.package, r.goos, r.goarch, r.output) == (
        "go1.23",
        "./cmd/hello",
        "linux",
        "amd64",
        "hello",
    )
    assert r.ldflags == "-s -w -buildid= -X main.version=v1.2.0"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t.replace('image   = "go1.23"', 'image   = "go9.99"'),
        lambda t: t.replace('goos    = "linux"', 'goos    = "plan9"'),
        lambda t: t.replace('goarch  = "amd64"', 'goarch  = "mips"'),
        lambda t: t.replace('"./cmd/hello"', '"cmd/hello"'),
        lambda t: t.replace('"./cmd/hello"', '"./cmd/../hello"'),
        lambda t: t.replace('"./cmd/hello"', '"./.."'),
        lambda t: t.replace('"./cmd/hello"', '"./cmd hello"'),
        lambda t: t.replace("-s -w", "-extld=gcc"),
        lambda t: t.replace('"hello"', '".."'),
        lambda t: t.replace('"hello"', '"."'),
        lambda t: t.replace('"hello"', '"../x"'),
        lambda t: t.replace('"hello"', '""'),
        lambda t: t.replace('output  = "hello"', "output  = 5"),
        lambda t: t.replace('output  = "hello"\n', ""),
        lambda t: t + 'extra = "x"\n',
        lambda t: t + '[other]\nk = "v"\n',
        lambda t: "[build]\n" + 'image = "go1.23"\n' + t,  # duplicate key
        lambda t: t.replace("[build]", "build = 1\n[x]"),
        lambda t: "not toml [",
        lambda t: "",
        lambda t: t + "# " + "x" * 5000,
    ],
)
def test_parse_recipe_rejects(genesis, mutate):
    assert parse_recipe(mutate(RECIPE).encode(), genesis) is None


def test_parse_recipe_rejects_non_utf8_and_garbage(genesis):
    assert parse_recipe(b"\xff\xfe[build]", genesis) is None
    assert parse_recipe(b"[" * 5000, genesis) is None


def test_recipe_allows_empty_ldflags(genesis):
    t = RECIPE.replace("-s -w -buildid= -X main.version=v1.2.0", "")
    assert parse_recipe(t.encode(), genesis).ldflags == ""


# --- envelope ------------------------------------------------------------------------------


def test_release_envelope_roundtrip(genesis, release_env):
    e = parse_envelope(release_env, genesis)
    assert e is not None
    assert (e.type, e.signer, e.body) == ("release", "ci-release", GOOD_BODY | {"tag": "v1.2.0"})
    assert e.msg_id == sha256_hex(canonical_json(release_env))
    assert e.raw == release_env


def test_attest_envelope_roundtrip_all_input_forms(genesis, attest):
    env = attest("builder3", "f" * 64)
    for form in (env, canonical_json(env), canonical_json(env).decode()):
        e = parse_envelope(form, genesis)
        assert e is not None and e.type == "attest" and e.signer == "builder3"
    assert parse_envelope(attest("builder3", "FAILED"), genesis).body["result"] == "FAILED"


def test_wrong_genesis_hash_rejects_envelope(genesis_dict, release_env):
    # same keys, different network: a replayed signature must not verify
    genesis_dict["network_id"] = "other-network"
    assert parse_envelope(release_env, parse_genesis(genesis_dict)) is None


def test_tampered_envelope_rejected(genesis, attest):
    env = attest("builder3", "f" * 64)
    env["body"]["result"] = "e" * 64
    assert parse_envelope(env, genesis) is None


def test_signer_mismatch_rejected(genesis, attest):
    env = attest("builder3", "f" * 64)
    env["signer"] = "builder4"  # signed by builder3's key
    assert parse_envelope(env, genesis) is None


def test_type_and_signer_role_must_match(genesis, keys, release_env):
    body = {"request_id": "a" * 64, "result": "FAILED"}
    # a release signer cannot attest, a builder cannot release
    assert (
        parse_envelope(
            make_envelope("attest", "ci-release", body, keys["ci-release"], genesis), genesis
        )
        is None
    )
    assert (
        parse_envelope(
            make_envelope("release", "builder1", GOOD_BODY, keys["builder1"], genesis), genesis
        )
        is None
    )
    assert (
        parse_envelope(make_envelope("attest", "nobody", body, keys["builder1"], genesis), genesis)
        is None
    )


def test_release_for_disallowed_repo_rejected(genesis, keys):
    body = GOOD_BODY | {"repo_url": "https://github.com/evil/repo"}
    assert (
        parse_envelope(
            make_envelope("release", "ci-release", body, keys["ci-release"], genesis), genesis
        )
        is None
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(extra=1),
        lambda e: e.pop("sig"),
        lambda e: e.update(v=True),
        lambda e: e.update(v=2),
        lambda e: e.update(type="other"),
        lambda e: e.update(type=["attest"]),
        lambda e: e.update(signer=5),
        lambda e: e.update(sig=e["sig"].upper()),
        lambda e: e.update(sig=e["sig"][:-2]),
        lambda e: e.update(sig=None),
        lambda e: e.update(body=None),
        lambda e: e["body"].update(extra=1),
        lambda e: e["body"].update(request_id="A" * 64),
        lambda e: e["body"].update(result="failed"),
        lambda e: e["body"].update(result="f" * 63),
    ],
)
def test_envelope_rejects_malformed(genesis, attest, mutate):
    env = attest("builder3", "f" * 64)
    mutate(env)
    assert parse_envelope(env, genesis) is None


def test_oversize_raw_rejected(genesis, release_env):
    padded = canonical_json(release_env) + b" " * 5000
    assert parse_envelope(padded, genesis) is None


@pytest.mark.parametrize(
    "raw",
    [
        None,
        5,
        [],
        "garbage",
        b"\xff\xfe",
        b'{"a":1,"a":2}',
        {"v": 1.5},
        {"v": 1, "type": "attest", "signer": "\ud800", "body": {}, "sig": "0" * 128},
        {"v": 1, "type": "attest", "signer": "builder1", "body": {"x": 0.5}, "sig": "0" * 128},
        {"v": 1, "type": "attest", "signer": ["x"], "body": {}, "sig": "0" * 128},
    ],
)
def test_parse_envelope_never_raises(genesis, raw):
    assert parse_envelope(raw, genesis) is None


def test_parse_envelope_deep_nesting_never_raises(genesis):
    deep = cur = {}
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    assert (
        parse_envelope(
            {"v": 1, "type": "attest", "signer": "builder1", "body": deep, "sig": "0" * 128},
            genesis,
        )
        is None
    )


# --- certificate ---------------------------------------------------------------------------


def _cert(release_env, attest, n=3):
    return {
        "v": 1,
        "genesis_hash": "a" * 64,
        "request": release_env,
        "attestations": [attest(f"builder{i}", "f" * 64) for i in range(1, n + 1)],
    }


def test_parse_certificate_accepts_good(genesis, release_env, attest):
    c = parse_certificate(canonical_json(_cert(release_env, attest)), genesis)
    assert c is not None
    assert c.genesis_hash == "a" * 64 and len(c.attestations) == 3 and c.request == release_env


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(extra=1),
        lambda c: c.pop("request"),
        lambda c: c.update(v=True),
        lambda c: c.update(v=2),
        lambda c: c.update(genesis_hash="A" * 64),
        lambda c: c.update(genesis_hash="a" * 63),
        lambda c: c.update(request=[]),
        lambda c: c.update(attestations=[]),
        lambda c: c.update(attestations={}),
        lambda c: c.update(attestations=[{}] * 17),
        lambda c: c.update(attestations=["x"]),
    ],
)
def test_parse_certificate_rejects(genesis, release_env, attest, mutate):
    cert = _cert(release_env, attest)
    mutate(cert)
    assert parse_certificate(canonical_json(cert), genesis) is None


def test_parse_certificate_limits_are_inclusive(genesis, release_env, attest):
    ok = _cert(release_env, attest)
    ok["attestations"] = [{}] * 16
    assert parse_certificate(canonical_json(ok), genesis) is not None


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b'{"v":1,"v":1}',
        b"[]",
        b"null",
        b"\xff",
        b" " * 70000,
        b'{"v":1.0}',
    ],
)
def test_parse_certificate_never_raises(genesis, raw):
    assert parse_certificate(raw, genesis) is None
