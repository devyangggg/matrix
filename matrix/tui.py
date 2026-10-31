"""Read-only Textual observatory over the builders' untrusted HTTP API."""

import asyncio
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any, ClassVar

from aiohttp import ClientError, ClientSession, ClientTimeout
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Footer, Header, Static

from .genesis import Genesis, Node
from .model import parse_envelope, request_id
from .select import selected
from .verdict import Verdict, verdict

_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_RESPONSE = 1024 * 1024


def _unique(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON key")
    return result


def _finite(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _reject(_: str) -> Any:
    raise ValueError("non-finite JSON constant")


@dataclass(frozen=True)
class ReleaseRow:
    id: str
    phase: str
    request: dict | None
    verdict: Verdict | None


class MatrixApp(App):
    """One current network snapshot; no database access or locally cached verdicts."""

    CSS = """
    #title { height: 2; padding: 0 1; }
    #rows { height: 1fr; }
    #pane { height: 40%; border: round $accent; }
    #content { padding: 1; }
    """
    BINDINGS: ClassVar[list[tuple[str, str, str]]] = [
        ("b", "builders", "Builders"),
        ("r", "releases", "Releases"),
        ("e", "evidence", "Evidence"),
        ("enter", "open", "Detail / proof"),
        ("l", "log", "Local log"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, genesis: Genesis, node: Node):
        super().__init__()
        self.genesis, self.node = genesis, node
        self.view = "builders"
        self.releases: list[ReleaseRow] = []
        self.evidence: list[dict] = []
        self.health: dict[str, tuple[str, str]] = {}
        self.selected_id: str | None = None
        self.proof: dict | None = None
        self.show_log = False
        self.log_text = ""
        self.online = False
        self._rendered_view: str | None = None
        self._polling = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("", id="title", markup=False)
        yield DataTable(id="rows", cursor_type="row")
        with VerticalScroll(id="pane"):
            yield Static("", id="content", markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        self.session = ClientSession(timeout=ClientTimeout(total=3))
        self.set_interval(1.0, self.refresh_snapshot)
        self.call_later(self.refresh_snapshot)
        self._render()

    async def on_unmount(self) -> None:
        await self.session.close()

    async def _json(self, node: Node, path: str) -> dict | None:
        try:
            async with self.session.get(f"http://{node.addr}{path}") as response:
                if response.status != 200:
                    return None
                raw = await response.content.read(_MAX_RESPONSE + 1)
                if len(raw) > _MAX_RESPONSE:
                    return None
                obj = json.loads(
                    raw, object_pairs_hook=_unique, parse_float=_finite, parse_constant=_reject
                )
                return obj if isinstance(obj, dict) else None
        except (ClientError, OSError, TimeoutError, ValueError):
            return None

    async def _text(self, path: str) -> str | None:
        try:
            async with self.session.get(f"http://{self.node.addr}{path}") as response:
                if response.status != 200:
                    return None
                raw = await response.content.read(65537)
                return raw.decode("utf-8", errors="replace") if len(raw) <= 65536 else None
        except (ClientError, OSError, TimeoutError, ValueError):
            return None

    async def _health(self, node: Node) -> tuple[str, str]:
        data = await self._json(node, "/v1/health")
        if data is None:
            return "unreachable", "-"
        if data.get("node_id") != node.id:
            return "wrong id", "-"
        seen = time.strftime("%H:%M:%S", time.localtime())
        return ("yes" if data.get("genesis_hash") == self.genesis.hash else "NO", seen)

    async def _release(self, summary: Any) -> ReleaseRow | None:
        if not isinstance(summary, dict):
            return None
        rid, phase = summary.get("id"), summary.get("phase")
        if not isinstance(rid, str) or _HEX64.fullmatch(rid) is None:
            return None
        detail, bundle = await asyncio.gather(
            self._json(self.node, f"/v1/requests/{rid}"),
            self._json(self.node, f"/v1/requests/{rid}/bundle"),
        )
        request = detail.get("request") if detail else None
        parsed = parse_envelope(request, self.genesis)
        if parsed is None or parsed.type != "release" or request_id(parsed.body) != rid:
            return ReleaseRow(rid, str(phase), None, Verdict("INVALID") if detail else None)
        envs = bundle.get("envelopes") if bundle else None
        result = verdict(request, envs, self.genesis) if isinstance(envs, list) else None
        return ReleaseRow(rid, str(phase), request, result)

    async def refresh_snapshot(self) -> None:
        if self._polling:
            return
        self._polling = True
        try:
            health, listing, records = await asyncio.gather(
                asyncio.gather(*(self._health(node) for node in self.genesis.nodes)),
                self._json(self.node, "/v1/requests?since=0"),
                self._json(self.node, "/v1/evidence?since=0"),
            )
            self.health = dict(zip((n.id for n in self.genesis.nodes), health, strict=True))
            summaries = listing.get("requests") if listing else None
            self.online = isinstance(summaries, list)
            if self.online:
                rows = await asyncio.gather(*(self._release(s) for s in summaries))
                self.releases = [row for row in rows if row is not None]
            else:
                self.releases = []
            items = records.get("evidence") if records else None
            self.evidence = (
                [e for e in items if isinstance(e, dict)] if isinstance(items, list) else []
            )
            if self.view == "proof" and self.proof is not None:
                prior = self.proof
                self.proof = next(
                    (
                        item
                        for item in self.evidence
                        if all(
                            item.get(k) == prior.get(k)
                            for k in ("id", "kind", "signer", "request_id")
                        )
                    ),
                    None,
                )
            if self.view == "detail" and self.show_log:
                await self._refresh_log()
            self._render()
        finally:
            self._polling = False

    async def _refresh_log(self) -> None:
        if self.selected_id:
            text = await self._text(f"/v1/requests/{self.selected_id}/log")
            self.log_text = text if text is not None else "Log unavailable"

    @staticmethod
    def _when(stamp: Any) -> str:
        if type(stamp) not in (int, float):
            return "-"
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stamp))
        except (OSError, OverflowError, ValueError):
            return "-"

    def _render(self) -> None:
        table = self.query_one("#rows", DataTable)
        cursor = table.cursor_row if self._rendered_view == self.view else 0
        pane = self.query_one("#pane", VerticalScroll)
        content = self.query_one("#content", Static)
        table.clear(columns=True)
        pane.display = self.view in ("detail", "proof")
        self.query_one("#title", Static).update(
            f"{self.view.title()} | node {self.node.id} | "
            f"{'online' if self.online else 'request API unavailable'}"
        )
        if self.view == "builders":
            table.add_columns("Operator", "Builder", "Address", "Reachable", "Genesis", "Last seen")
            for node in self.genesis.nodes:
                state, seen = self.health.get(node.id, ("unreachable", "-"))
                table.add_row(
                    node.operator,
                    node.id,
                    "wrong id"
                    if state == "wrong id"
                    else "no"
                    if state == "unreachable"
                    else "yes",
                    state if state in ("yes", "NO") else "-",
                    seen,
                )
        elif self.view == "releases":
            table.add_columns("ID", "Repo @ tag", "Phase", "Attestations", "Quorum", "Verdict")
            for row in self.releases:
                v = row.verdict
                counts = {} if v is None else v.results
                progress = max(
                    (
                        sum(result == value for result in counts.values())
                        for value in counts.values()
                    ),
                    default=0,
                )
                body = row.request["body"] if row.request else None
                table.add_row(
                    row.id[:8],
                    f"{body['repo_url']}@{body['tag']}" if body else "unverified",
                    row.phase,
                    f"{len(counts)}/{self.genesis.replicas}" if v else "-",
                    f"{progress}/{self.genesis.threshold}" if v else "-",
                    v.state if v else "UNAVAILABLE",
                )
        elif self.view == "detail":
            row = next((r for r in self.releases if r.id == self.selected_id), None)
            table.add_columns("Builder", "Result", "Quorum match")
            v = row.verdict if row else None
            quorum = (
                v.hash
                if v and v.state == "AGREED"
                else "FAILED"
                if v and v.state == "BUILD_FAILED"
                else None
            )
            if row:
                for signer in selected(row.id, self.genesis.nodes, self.genesis.replicas):
                    result = v.results.get(signer) if v else None
                    table.add_row(
                        signer,
                        "EQUIVOCATED" if v and signer in v.equivocators else result or "-",
                        "yes"
                        if result and result == quorum
                        else "no"
                        if result and quorum
                        else "-",
                    )
            body = row.request["body"] if row and row.request else None
            label = f"{body['repo_url']}@{body['tag']}" if body else "unverified request"
            content.update(
                f"{self.selected_id} | {label} | {v.state if v else 'UNAVAILABLE'}\n"
                + (f"\nLocal log ({self.node.id}):\n{self.log_text}" if self.show_log else "")
            )
        elif self.view == "evidence":
            table.add_columns("Kind", "Signer", "Release", "Time")
            for item in self.evidence:
                when = self._when(item.get("created_at"))
                table.add_row(
                    str(item.get("kind", "?")),
                    str(item.get("signer", "?")),
                    str(item.get("request_id", "?"))[:8],
                    when,
                )
        elif self.view == "proof":
            table.add_columns("Proof")
            table.add_row("Untrusted remote evidence (not independently verified)")
            content.update(
                json.dumps(self.proof, indent=2, ensure_ascii=False)
                if self.proof is not None
                else "Evidence unavailable"
            )

        self._rendered_view = self.view
        if table.row_count:
            table.move_cursor(row=min(cursor, table.row_count - 1), scroll=False)

    def action_builders(self) -> None:
        self.view = "builders"
        self._render()

    def action_releases(self) -> None:
        self.view = "releases"
        self._render()

    def action_evidence(self) -> None:
        self.view = "evidence"
        self._render()

    def action_open(self) -> None:
        index = self.query_one("#rows", DataTable).cursor_row
        if self.view == "releases" and 0 <= index < len(self.releases):
            self.selected_id = self.releases[index].id
            self.show_log = False
            self.view = "detail"
            self._render()
        elif self.view == "evidence" and 0 <= index < len(self.evidence):
            self.proof = self.evidence[index]
            self.view = "proof"
            self._render()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_open()

    async def action_log(self) -> None:
        if self.view != "detail":
            return
        self.show_log = not self.show_log
        if self.show_log:
            await self._refresh_log()
        self._render()


def run_tui(genesis: Genesis, node: Node) -> None:
    MatrixApp(genesis, node).run()
