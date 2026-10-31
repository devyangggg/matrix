from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .genesis import Genesis
from .model import parse_envelope, request_id
from .select import selected


@dataclass(frozen=True)
class Verdict:
    state: str  # AGREED | BUILD_FAILED | NOT_REPRODUCIBLE | PENDING | INVALID
    hash: str | None = None  # set for AGREED
    results: dict[str, str] = field(default_factory=dict)  # signer -> result (non-equivocators)
    equivocators: frozenset[str] = frozenset()


def verdict(request_env: Any, envelopes: Iterable[Any], g: Genesis) -> Verdict:
    """RFC §7.7. The caller picks the request; nothing in `envelopes` can replace it."""
    try:
        req = parse_envelope(request_env, g)
        if req is None or req.type != "release":
            return Verdict("INVALID")
        rid = request_id(req.body)
        sel = set(selected(rid, g.nodes, g.replicas))

        seen: dict[str, set[str]] = defaultdict(set)  # signer -> distinct results
        for raw in envelopes:
            e = parse_envelope(raw, g)  # None unless schema, formats and signature are valid
            if e and e.type == "attest" and e.body["request_id"] == rid and e.signer in sel:
                seen[e.signer].add(e.body["result"])

        equivocators = frozenset(s for s, rs in seen.items() if len(rs) > 1)
        results = {s: next(iter(rs)) for s, rs in seen.items() if len(rs) == 1}
        counts = Counter(results.values())
        quorum = [r for r, k in counts.items() if k >= g.threshold]
        # Equivocators and silent builders may still vote, so they only ever delay a verdict.
        outstanding = len(sel) - len(results)

        def v(state: str, h: str | None = None) -> Verdict:
            return Verdict(state, h, results, equivocators)

        if len(quorum) > 1:
            return v("NOT_REPRODUCIBLE")  # two quorums: two honest builders disagree
        if quorum:
            return v("BUILD_FAILED") if quorum[0] == "FAILED" else v("AGREED", quorum[0])
        if max(counts.values(), default=0) + outstanding < g.threshold:
            return v("NOT_REPRODUCIBLE")  # no result can still reach T
        return v("PENDING")
    except Exception:  # noqa: BLE001  never raises (invariant 1); fail closed
        return Verdict("INVALID")
