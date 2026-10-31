import hashlib

from matrix.select import selected

RID = "ab" * 32


def _expected(rid, nodes, r):
    key = lambda n: hashlib.sha256(f"{rid}:{n.pubkey}".encode()).hexdigest()
    return [n.id for n in sorted(nodes, key=key)][:r]


def test_matches_rfc_formula(genesis):
    assert selected(RID, genesis.nodes, 5) == _expected(RID, genesis.nodes, 5)


def test_r_equals_n_selects_every_node(genesis):
    assert sorted(selected(RID, genesis.nodes, 8)) == sorted(n.id for n in genesis.nodes)


def test_independent_of_input_order(genesis):
    assert selected(RID, genesis.nodes, 5) == selected(RID, tuple(reversed(genesis.nodes)), 5)


def test_prefix_property_and_request_dependence(genesis):
    assert selected(RID, genesis.nodes, 3) == selected(RID, genesis.nodes, 5)[:3]
    orders = {tuple(selected(f"{i:064x}", genesis.nodes, 8)) for i in range(20)}
    assert len(orders) > 1  # the request id actually steers the order
