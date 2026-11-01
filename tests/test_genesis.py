import json

import pytest

from matrix.canon import canonical_json, sha256_hex
from matrix.genesis import GenesisError, file_genesis_hash, load_genesis, parse_genesis


def _set(path, value):
    def mutate(raw):
        d = raw
        for p in path[:-1]:
            d = d[p]
        d[path[-1]] = value

    return mutate


def _del(key):
    return lambda raw: raw.pop(key)


def _short_nodes(raw):
    raw["nodes"] = raw["nodes"][:7]  # n=7 < 4f


def _three_on_one_operator(raw):
    for n in raw["nodes"][:3]:
        n["operator"] = "laptopA"  # 3 > f


BAD = {
    "extra key": _set(["extra"], 1),
    "missing key": _del("nodes"),
    "f negative": _set(["f"], -1),
    "f bool": _set(["f"], True),
    "f float": _set(["f"], 2.0),
    "n < 4f": _short_nodes,
    "replicas > n": _set(["replicas"], 9),
    "replicas < 2f+1": _set(["replicas"], 4),
    "threshold != f+1": _set(["threshold"], 2),
    "timeout >= ttl": _set(["build_timeout_s"], 3600),
    "operator over f": _three_on_one_operator,
    "empty operator": _set(["nodes", 0, "operator"], ""),
    "bad network_id": _set(["network_id"], "bad id"),
    "node id bad chars": _set(["nodes", 0, "id"], "bad id!"),
    "node id too long": _set(["nodes", 0, "id"], "x" * 33),
    "node id dup": _set(["nodes", 1, "id"], "builder1"),
    "signer id dup with node": _set(["release_signers", 0, "id"], "builder1"),
    "pubkey upper": lambda r: r["nodes"][0].update(pubkey=r["nodes"][0]["pubkey"].upper()),
    "pubkey dup across lists": lambda r: r["nodes"][0].update(
        pubkey=r["release_signers"][0]["pubkey"]
    ),
    "addr no port": _set(["nodes", 0, "addr"], "127.0.0.1"),
    "addr port too big": _set(["nodes", 0, "addr"], "127.0.0.1:70000"),
    "addr bad host": _set(["nodes", 0, "addr"], "a b:7700"),
    "addr explicit null": _set(["nodes", 0, "addr"], None),
    "addr not a string": _set(["nodes", 0, "addr"], 7700),
    "repo not github": _set(["allowed_repos"], ["https://example.com/a/b"]),
    "repo trailing slash": _set(["allowed_repos"], ["https://github.com/a/b/"]),
    "repo http": _set(["allowed_repos"], ["http://github.com/a/b"]),
    "image tag not digest": _set(["allowed_images"], {"go1.23": "golang:1.23"}),
    "image short digest": _set(["allowed_images"], {"go1.23": "golang@sha256:abc"}),
    "empty repos": _set(["allowed_repos"], []),
    "empty images": _set(["allowed_images"], {}),
    "empty goos": _set(["allowed_goos"], []),
    "empty goarch": _set(["allowed_goarch"], []),
    "empty signers": _set(["release_signers"], []),
    "node extra key": _set(["nodes", 0, "extra"], 1),
    "node not a dict": _set(["nodes", 0], "builder1"),
    "id not a string": _set(["nodes", 0, "id"], 5),
}


@pytest.mark.parametrize("mutate", BAD.values(), ids=BAD.keys())
def test_rejects_bad_genesis(genesis_dict, mutate):
    mutate(genesis_dict)
    with pytest.raises(GenesisError):
        parse_genesis(genesis_dict)


def test_loads_valid_genesis(genesis, genesis_dict):
    assert genesis.f == 2 and genesis.threshold == 3 and genesis.replicas == 8
    assert len(genesis.nodes) == 8
    assert genesis.node("builder3").operator == "laptopB"
    assert genesis.node("nope") is None
    assert genesis.signer("ci-release") is not None
    assert genesis.signer("builder1") is None
    assert genesis.hash == sha256_hex(canonical_json(genesis_dict))


def test_full_profile_loads(genesis_dict):
    genesis_dict.update(build_timeout_s=150, sync_interval_s=10)
    assert parse_genesis(genesis_dict).build_timeout_s == 150


def test_hash_ignores_file_formatting(tmp_path, genesis_dict):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(genesis_dict))
    b.write_text(json.dumps(dict(reversed(genesis_dict.items())), indent=4))
    assert file_genesis_hash(str(a)) == file_genesis_hash(str(b)) == load_genesis(str(a)).hash


def test_hash_changes_with_content(genesis_dict):
    h = parse_genesis(genesis_dict).hash
    genesis_dict["allowed_repos"].append("https://github.com/org/other")
    assert parse_genesis(genesis_dict).hash != h


@pytest.mark.parametrize(
    "content",
    ['{"f":2,"f":2}', "[]", "not json", "", '{"f":2.0}', "null"],
)
def test_load_rejects_unparsable_files(tmp_path, content):
    p = tmp_path / "g.json"
    p.write_text(content)
    with pytest.raises(GenesisError):
        load_genesis(str(p))


def test_load_missing_file(tmp_path):
    with pytest.raises(GenesisError):
        load_genesis(str(tmp_path / "missing.json"))


def test_addr_is_optional(genesis_dict):
    # ceremony genesis (RFC rev 5 §7.2): no addresses, members are found by signed hellos
    for n in genesis_dict["nodes"]:
        del n["addr"]
    g = parse_genesis(genesis_dict)
    assert all(n.addr is None for n in g.nodes)


def test_addr_may_be_mixed_and_changes_the_hash(genesis_dict):
    with_addr = parse_genesis(genesis_dict)
    del genesis_dict["nodes"][0]["addr"]
    g = parse_genesis(genesis_dict)
    assert g.nodes[0].addr is None and g.nodes[1].addr == "127.0.0.1:7701"
    assert g.hash != with_addr.hash  # why addresses must not live in a real network's genesis
