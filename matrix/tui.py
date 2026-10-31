"""Textual TUI: Builders, Releases, Detail, Evidence (RFC §7.12, LLD §3.14).

Talks to builders over the HTTP API only and never opens the database. Every second it polls
the chosen node and each builder's /v1/health, runs verdict() locally on what it fetched, and
keeps nothing beyond the last poll result.
"""

import asyncio
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Footer, Header, Static

from .cli import CLIENT, builder_rows, check_proof
from .genesis import Genesis
from .model import parse_envelope, request_id
from .net import PeerClient
from .verdict import Verdict, verdict

MAX_RELEASES = 20  # newest first; bounds the per-second polling load
MAX_LOG = 65536
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


@dataclass(frozen=True)
class Release:
    id: str
    body: dict | None  # None if the node served no valid request for this id
    phase: str
    verdict: Verdict

    def counts(self) -> tuple[int, int]:
        """(builders that attested, largest number agreeing on one result)."""
        v = self.verdict
        top = max(Counter(v.results.values()).values(), default=0)
        return len(v.results) + len(v.equivocators), top


# polling (plain async functions, so they can be tested without a terminal)


async def poll_health(peers: PeerClient, g: Genesis) -> dict[str, dict | None]:
    replies = await asyncio.gather(*(peers.get_json(n.id, "/v1/health") for n in g.nodes))
    return {n.id: r if isinstance(r, dict) else None for n, r in zip(g.nodes, replies)}


async def poll_releases(peers: PeerClient, g: Genesis, node_id: str) -> list[Release]:
    lst = await peers.get_json(node_id, "/v1/requests?since=0")
    items = lst.get("requests") if isinstance(lst, dict) else None
    if not isinstance(items, list):
        return []
    items = [
        i
        for i in items
        if isinstance(i, dict)
        and isinstance(i.get("id"), str)
        and _HEX64.fullmatch(i["id"])
        and isinstance(i.get("received_at"), (int, float))
    ]
    items = sorted(items, key=lambda i: i["received_at"], reverse=True)[:MAX_RELEASES]
    requests, bundles = await asyncio.gather(
        asyncio.gather(
            *(peers.get_json(node_id, f"/v1/requests/{i['id']}") for i in items)
        ),
        asyncio.gather(
            *(peers.get_json(node_id, f"/v1/requests/{i['id']}/bundle") for i in items)
        ),
    )
    out = []
    for i, r, b in zip(items, requests, bundles):
        req = r.get("request") if isinstance(r, dict) else None
        e = parse_envelope(req, g)
        phase = i["phase"] if isinstance(i.get("phase"), str) else "?"
        if e is None or e.type != "release" or request_id(e.body) != i["id"]:
            out.append(Release(i["id"], None, phase, Verdict("INVALID")))
            continue
        envs = b.get("envelopes") if isinstance(b, dict) else None
        if not isinstance(envs, list):
            out.append(Release(i["id"], e.body, phase, Verdict("INVALID")))
            continue
        out.append(Release(i["id"], e.body, phase, verdict(e.raw, envs, g)))
    return out


async def poll_evidence(peers: PeerClient, node_id: str) -> list[dict]:
    r = await peers.get_json(node_id, "/v1/evidence?since=0")
    items = r.get("evidence") if isinstance(r, dict) else None
    if not isinstance(items, list):
        return []
    keys = ("kind", "signer", "request_id")
    return [
        i for i in items if isinstance(i, dict) and all(isinstance(i.get(k), str) for k in keys)
    ]


async def poll_log(peers: PeerClient, node_id: str, rid: str) -> str:
    data = await peers.get_bytes(node_id, f"/v1/requests/{rid}/log", MAX_LOG)
    return "(no log on this builder)" if data is None else data.decode("utf-8", "replace")


def _time(t: object) -> str:
    if not isinstance(t, (int, float)) or not 0 <= t < 1e11:
        return "-"
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _verdict_text(v: Verdict) -> Text:
    style = {"AGREED": "green", "PENDING": "yellow"}.get(v.state, "red")
    label = f"AGREED {v.hash[:12]}" if v.state == "AGREED" else v.state
    return Text(label, style=style)


# the app


class MatrixTui(App):
    TITLE = "Matrix"
    BINDINGS: ClassVar = [
        Binding("b", "show('builders')", "Builders"),
        Binding("r", "show('releases')", "Releases"),
        Binding("e", "show('evidence')", "Evidence"),
        Binding("l", "toggle_log", "Log"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, g: Genesis, node_id: str, peers: PeerClient | None = None):
        super().__init__()
        self.g, self.node_id = g, node_id
        self.view = "builders"
        self.detail_id: str | None = None
        self.show_log = False
        self.extra = ""  # log tail or proof JSON under the table
        self.health: dict[str, dict | None] = {}
        self.releases: list[Release] = []
        self.evidence: list[dict] = []
        self.peers = peers  # tests inject a fake; otherwise created on mount
        self._busy = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(id="status")
        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
        yield Static(id="extra")
        yield Footer()

    async def on_mount(self) -> None:
        if self.peers is None:
            self.peers = PeerClient(self.g, CLIENT)
        self.set_interval(1.0, self.poll)
        await self.poll()

    async def on_unmount(self) -> None:
        if self.peers is not None:
            await self.peers.close()

    async def poll(self) -> None:
        if self._busy or self.peers is None:
            return  # a slow builder must not stack up overlapping polls
        self._busy = True
        try:
            self.health, self.releases, self.evidence = await asyncio.gather(
                poll_health(self.peers, self.g),
                poll_releases(self.peers, self.g, self.node_id),
                poll_evidence(self.peers, self.node_id),
            )
            if self.view == "detail" and self.show_log and self.detail_id:
                self.extra = await poll_log(self.peers, self.node_id, self.detail_id)
        finally:
            self._busy = False
        self.render_view()

    # actions

    def action_show(self, view: str) -> None:
        self.view, self.extra, self.show_log = view, "", False
        self.render_view(reset=True)

    async def action_toggle_log(self) -> None:
        if self.view != "detail" or self.detail_id is None or self.peers is None:
            return
        self.show_log = not self.show_log
        self.extra = (
            await poll_log(self.peers, self.node_id, self.detail_id) if self.show_log else ""
        )
        self.render_view()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = event.row_key.value
        if self.view == "releases" and key:
            self.view, self.detail_id, self.show_log, self.extra = "detail", key, False, ""
            self.render_view(reset=True)
        elif self.view == "evidence" and key is not None:
            item = self.evidence[int(key)] if int(key) < len(self.evidence) else None
            if item is not None:
                ok = "valid" if check_proof(item, self.g) else "unverified"
                self.extra = f"proof ({ok}):\n" + json.dumps(item.get("proof"), indent=2)
                self.render_view()

    # rendering

    def render_view(self, reset: bool = False) -> None:
        table = self.query_one("#table", DataTable)
        row = 0 if reset else table.cursor_row
        table.clear(columns=True)
        status = getattr(self, f"_render_{self.view}")(table)
        reachable = sum(1 for h in self.health.values() if h is not None)
        self.query_one("#status", Static).update(
            f"[b]{self.view.upper()}[/b]  node {self.node_id}  "
            f"builders up {reachable}/{len(self.g.nodes)}  {status}"
        )
        self.query_one("#extra", Static).update(Text(self.extra))
        if table.row_count:
            table.move_cursor(row=min(row, table.row_count - 1))

    def _render_builders(self, t: DataTable) -> str:
        t.add_columns("operator", "builder", "address", "reachable", "genesis", "clock")
        for n in sorted(self.g.nodes, key=lambda n: n.operator):
            h = self.health.get(n.id)
            match = (
                h is not None and h.get("genesis_hash") == self.g.hash and h.get("node_id") == n.id
            )
            t.add_row(
                n.operator,
                n.id,
                n.addr,
                Text("yes", "green") if h else Text("no", "red"),
                Text("match", "green") if match else Text("-" if h is None else "MISMATCH", "red"),
                _time(h.get("now")) if h else "-",
            )
        return f"genesis {self.g.hash[:16]}"

    def _render_releases(self, t: DataTable) -> str:
        t.add_columns("id", "release", "phase", "attested", "quorum", "verdict")
        for r in self.releases:
            att, top = r.counts()
            name = f"{r.body['repo_url'].rsplit('/', 1)[-1]}@{r.body['tag']}" if r.body else "?"
            t.add_row(
                r.id[:12],
                name,
                r.phase,
                f"{att}/{self.g.replicas}",
                f"{min(top, self.g.threshold)}/{self.g.threshold}",
                _verdict_text(r.verdict),
                key=r.id,
            )
        return "Enter: detail"

    def _render_detail(self, t: DataTable) -> str:
        t.add_columns("builder", "operator", "result", "matches quorum")
        r = next((r for r in self.releases if r.id == self.detail_id), None)
        if r is None:
            return f"release {self.detail_id or '?'} not on this node"
        style = {"ok": "green", "": ""}
        for nid, op, res, mark in builder_rows(self.g, r.id, r.verdict):
            t.add_row(nid, op, res, Text(mark or "-", style.get(mark, "red")))
        name = f"{r.body['repo_url']}@{r.body['tag']}" if r.body else "?"
        return f"{name}  " + _verdict_text(r.verdict).plain + "  l: log tail"

    def _render_evidence(self, t: DataTable) -> str:
        t.add_columns("kind", "signer", "release", "time", "proof")
        names = {r.id: f"{r.body['tag']} ({r.id[:8]})" for r in self.releases if r.body}
        for i, e in enumerate(self.evidence):
            ok = check_proof(e, self.g)
            proof = Text("valid", "green") if ok else Text("unverified", "yellow")
            t.add_row(
                Text(e["kind"], "red"),
                e["signer"],
                names.get(e["request_id"], e["request_id"][:12]),
                _time(e.get("created_at")),
                proof,
                key=str(i),
            )
        return "Enter: proof JSON"


def run_tui(g: Genesis, node_id: str) -> int:
    MatrixTui(g, node_id).run()
    return 0


def main() -> None:
    from .cli import run

    sys.exit(run(["tui", *sys.argv[1:]]))
