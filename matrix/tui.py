"""Textual TUI: Builders, Releases, Detail, Evidence (RFC §7.12, LLD §3.14).

Talks to builders over the HTTP API only and never opens the database. Every second it polls
the laptop's own builder (--node, loopback by default: the only place its build log is served),
the verified hellos it knows (/v1/peers) and each builder's /v1/health, runs verdict() locally on
what it fetched, and keeps nothing beyond the last poll result.
"""

import asyncio
import curses
import json
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Static

from .cli import CLIENT, ClientBook, builder_rows, check_proof, refresh
from .discovery import AddressBook
from .genesis import Genesis
from .model import parse_envelope, request_id
from .net import PeerClient
from .verdict import Verdict, verdict

MAX_RELEASES = 20  # newest first; bounds the per-second polling load
MAX_LOG = 65536
_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)

_COLORS = {
    "background": "#000000",
    "text": "#FFFFFF",
    "muted": "#A0A0A0",
    "blue": "#4287f5",
    "green": "#7DD3C0",
    "yellow": "#E6B86B",
    "red": "#D68198",
}
_FONT = {
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "A": [" ### ", "#   #", "#####", "#   #", "#   #"],
    "T": ["#####", "  #  ", "  #  ", "  #  ", "  #  "],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "I": ["#####", "  #  ", "  #  ", "  #  ", "#####"],
    "X": ["#   #", " # # ", "  #  ", " # # ", "#   #"],
}
_TAGLINE = "R E L E A S E   O B S E R V A T O R Y"
_INTRO_SECONDS = 2.0


def _intro_colors() -> dict[str, int]:
    """Curses uses the nearest palette colours; Textual uses truecolour when available."""
    if not curses.has_colors():
        return dict.fromkeys(("purple", "green", "muted", "fade1", "fade2", "text", "blue"), 0)
    curses.start_color()
    try:
        curses.use_default_colors()
        background = -1
    except curses.error:
        background = curses.COLOR_BLACK
    palette = (
        (183, curses.COLOR_MAGENTA),
        (121, curses.COLOR_CYAN),
        (245, curses.COLOR_WHITE),
        (249, curses.COLOR_WHITE),
        (252, curses.COLOR_WHITE),
        (255, curses.COLOR_WHITE),
        (69, curses.COLOR_BLUE),  # nearest 256-colour match to dashboard #4287f5
    )
    for pair, (indexed, basic) in enumerate(palette, 1):
        curses.init_pair(pair, indexed if curses.COLORS >= 256 else basic, background)
    return dict(
        zip(
            ("purple", "green", "muted", "fade1", "fade2", "text", "blue"),
            (curses.color_pair(i) for i in range(1, 8)),
        )
    )


def _put(win: curses.window, y: int, x: int, text: str, attr: int = 0) -> None:
    rows, cols = win.getmaxyx()
    if 0 <= y < rows and 0 <= x < cols:
        try:
            win.addstr(y, x, text[: cols - x], attr)
        except curses.error:
            pass  # Some terminals refuse to write their bottom-right cell.


def _intro_frame(win: curses.window, elapsed: float, colors: dict[str, int]) -> None:
    """Render one bounded frame; elapsed time determines the four animation phases."""
    rows, cols = win.getmaxyx()
    win.erase()
    if cols < 42 or rows < 10:
        label = "[ MATRIX ]"
        _put(win, rows // 2, max(0, (cols - len(label)) // 2), label, colors["blue"])
        return

    sx, sy = (2 if cols >= 84 else 1), (2 if rows >= 20 else 1)
    lines = [
        (" ".join(_FONT[letter][row] for letter in "MATRIX"))
        .replace("#", "█" * sx)
        .replace(" ", " " * sx)
        for row in range(5)
    ]
    width, height = len(lines[0]), 5 * sy
    left, top = (cols - width) // 2, max(0, (rows - height - 3) // 2)
    centre = cols // 2

    if elapsed < 0.3:
        extent = 1 + int((height - 1) * elapsed / 0.3)
        bracket_top = top + (height - extent) // 2
        bracket_left, bracket_right = centre - 1, centre
    else:
        extent, bracket_top = height, top
        slide = min(1.0, max(0.0, (elapsed - 0.3) / 0.4))
        slide = 1 - (1 - slide) ** 3
        bracket_left = round(centre - 1 + (left - 2 - centre + 1) * slide)
        bracket_right = round(centre + (left + width + 1 - centre) * slide)
    for offset in range(extent):
        if extent == 1:
            lhs, rhs = "[", "]"
        elif offset == 0:
            lhs, rhs = "┌", "┐"
        elif offset == extent - 1:
            lhs, rhs = "└", "┘"
        else:
            lhs, rhs = "│", "│"
        if elapsed >= 1.67:
            stage = min(4, int((elapsed - 1.67) / 0.33 * 5))
            lhs = rhs = ("▓", "▒", "░", " ", " ")[stage]
        _put(win, bracket_top + offset, bracket_left, lhs, colors["purple"])
        _put(win, bracket_top + offset, bracket_right, rhs, colors["purple"])

    if elapsed < 0.3:
        return
    reveal = min(1.0, (elapsed - 0.3) / 0.82)
    radius = (width / 2 + 1) * (1 - (1 - reveal) ** 3)
    shimmer = (elapsed - 1.12) / 0.36 * (width + 4) - 2
    for row, line in enumerate(lines):
        for col, cell in enumerate(line):
            if cell != "█" or abs(col - (width - 1) / 2) > radius:
                continue
            attr = colors["blue"]
            if (elapsed < 1.12 and abs(abs(col - (width - 1) / 2) - radius) < 1.5) or (
                1.12 <= elapsed < 1.48 and abs(col - shimmer) < 2
            ):
                attr = colors["green"]
            y = top + row * sy
            if elapsed >= 1.67:
                progress = (elapsed - 1.67) / 0.33
                stage = min(4, int(progress * 5 + ((col * 7 + row * 11) % 4) / 5))
                cell = ("█", "▓", "▒", "░", " ")[stage]
                y -= min(2, int(progress * 3))
            for vertical in range(sy):
                _put(win, y + vertical, left + col, cell, attr)

    if 1.12 <= elapsed < 1.67:
        step = min(3, int((elapsed - 1.12) / 0.36 * 4))
        attr = colors[("muted", "fade1", "fade2", "text")[step]]
        _put(win, top + height + 1, max(0, (cols - len(_TAGLINE)) // 2), _TAGLINE, attr)


def _intro(win: curses.window) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    win.nodelay(True)
    win.keypad(True)
    colors = _intro_colors()
    start = time.monotonic()
    while True:
        if win.getch() != -1:  # Any key skips the intro, including on its first frame.
            return
        elapsed = time.monotonic() - start
        if elapsed >= _INTRO_SECONDS:
            return
        try:
            size = os.get_terminal_size(sys.stdout.fileno())
            if (size.lines, size.columns) != win.getmaxyx():
                curses.resizeterm(size.lines, size.columns)
        except (OSError, curses.error):
            pass  # The next frame still clips to curses' current bounds.
        _intro_frame(win, elapsed, colors)
        win.refresh()
        time.sleep(min(0.035, _INTRO_SECONDS - elapsed))


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
        asyncio.gather(*(peers.get_json(node_id, f"/v1/requests/{i['id']}") for i in items)),
        asyncio.gather(*(peers.get_json(node_id, f"/v1/requests/{i['id']}/bundle") for i in items)),
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
    if data is None:  # also what a remote node answers: logs never leave their own laptop
        return "(no log: logs are only readable on the builder's own laptop)"
    return data.decode("utf-8", "replace")


def _time(t: object) -> str:
    if not isinstance(t, (int, float)) or not 0 <= t < 1e11:
        return "-"
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _verdict_text(v: Verdict) -> Text:
    style = {"AGREED": _COLORS["green"], "PENDING": _COLORS["yellow"]}.get(v.state, _COLORS["red"])
    label = f"AGREED {v.hash[:12]}" if v.state == "AGREED" else v.state
    return Text(label, style=style)


def _styled(value: str, colour: str = "text") -> Text:
    return Text(value, style=_COLORS[colour])


def _divider(width: int, split: int) -> Text:
    """A single blue rule whose centre joins the peers/requests separator."""
    if width <= 0:
        return _styled("", "blue")
    join = max(0, min(width - 1, split))
    return _styled("─" * join + "┴" + "─" * (width - join - 1), "blue")


# the app


class MatrixTui(App):
    TITLE = "MATRIX"
    CSS = f"""
    Screen {{
        background: {_COLORS["background"]};
        color: {_COLORS["text"]};
    }}
    #dashboard {{
        height: 1fr;
        background: {_COLORS["background"]};
        border: solid {_COLORS["blue"]};
        border-title-color: {_COLORS["blue"]};
    }}
    #top {{
        height: 52%;
        min-height: 8;
        background: {_COLORS["background"]};
    }}
    #peers-panel {{
        width: 42%;
        border-right: solid {_COLORS["blue"]};
        background: {_COLORS["background"]};
    }}
    #requests-panel, #details-panel {{
        width: 1fr;
        background: {_COLORS["background"]};
    }}
    #details-panel {{
        height: 1fr;
    }}
    .panel-title {{
        height: 1;
        padding: 0 1;
        color: {_COLORS["blue"]};
        background: {_COLORS["background"]};
        text-style: bold;
    }}
    #divider {{
        height: 1;
        color: {_COLORS["blue"]};
        background: {_COLORS["background"]};
    }}
    DataTable, #details, #extra {{
        background: {_COLORS["background"]};
        color: {_COLORS["text"]};
        scrollbar-size: 0 0;
    }}
    DataTable, #details {{
        height: 1fr;
    }}
    DataTable > .datatable--header {{
        background: {_COLORS["background"]};
        color: {_COLORS["blue"]};
    }}
    DataTable:focus {{
        background-tint: {_COLORS["background"]} 0%;
    }}
    DataTable:focus > .datatable--header {{
        background-tint: {_COLORS["background"]} 0%;
    }}
    DataTable:dark > .datatable--even-row {{
        background: {_COLORS["background"]};
    }}
    DataTable > .datatable--even-row, DataTable > .datatable--odd-row,
    DataTable > .datatable--cursor, DataTable:focus > .datatable--cursor,
    DataTable > .datatable--fixed-cursor, DataTable > .datatable--header-cursor {{
        background: {_COLORS["background"]};
    }}
    DataTable:focus > .datatable--cursor {{
        color: {_COLORS["blue"]};
        text-style: bold;
    }}
    #details {{
        padding: 0 1;
        overflow-y: auto;
    }}
    #extra {{
        height: auto;
        max-height: 40%;
        padding: 0 1;
        overflow-y: auto;
        color: {_COLORS["muted"]};
    }}
    Footer, FooterKey, FooterLabel {{
        background: {_COLORS["background"]};
        color: {_COLORS["muted"]};
    }}
    FooterKey .footer-key--key {{
        color: {_COLORS["blue"]};
        background: {_COLORS["background"]};
    }}
    FooterKey .footer-key--description {{
        color: {_COLORS["muted"]};
        background: {_COLORS["background"]};
    }}
    """
    BINDINGS: ClassVar = [
        Binding("b", "show('builders')", "Builders"),
        Binding("r", "show('releases')", "Releases"),
        Binding("e", "show('evidence')", "Evidence"),
        Binding("l", "toggle_log", "Log"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        g: Genesis,
        local: str,
        peers: PeerClient | None = None,
        local_id: str | None = None,
        book: ClientBook | None = None,
    ):
        super().__init__()
        self.g, self.local = g, local
        self.node_id = local_id  # the local builder's genesis id, from its /v1/health
        self.book = book
        self._own = peers is None  # real client: refresh the book from --node every poll
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
        with Vertical(id="dashboard"):
            with Horizontal(id="top"):
                with Vertical(id="peers-panel"):
                    yield Static(id="peers-title", classes="panel-title")
                    yield DataTable(id="peers", cursor_type="none")
                with Vertical(id="requests-panel"):
                    yield Static(id="requests-title", classes="panel-title")
                    yield DataTable(id="table", cursor_type="row")
            yield Static(id="divider")
            with Vertical(id="details-panel"):
                yield Static(id="details-title", classes="panel-title")
                yield Static(id="details")
                yield Static(id="extra")
        yield Footer(show_command_palette=False, compact=True)

    async def on_mount(self) -> None:
        if self.peers is None:
            self.book = ClientBook(self.g, self.local)
            self.peers = PeerClient(self.g, CLIENT, self.book)
        self.set_interval(1.0, self.poll)
        await self.poll()
        self.query_one("#table", DataTable).focus()

    async def on_unmount(self) -> None:
        if self.peers is not None:
            await self.peers.close()

    async def poll(self) -> None:
        if self._busy or self.peers is None:
            return  # a slow builder must not stack up overlapping polls
        self._busy = True
        try:
            if self._own:
                await refresh(self.peers, self.book)
                self.node_id = self.book.local_id
            if self.node_id is None:  # no builder answers at --node: show the peers only
                self.health = await poll_health(self.peers, self.g)
                self.releases, self.evidence = [], []
            else:
                self.health, self.releases, self.evidence = await asyncio.gather(
                    poll_health(self.peers, self.g),
                    poll_releases(self.peers, self.g, self.node_id),
                    poll_evidence(self.peers, self.node_id),
                )
            if self.node_id and self.view == "detail" and self.show_log and self.detail_id:
                self.extra = await poll_log(self.peers, self.node_id, self.detail_id)
        finally:
            self._busy = False
        self.render_view()

    # actions

    def action_show(self, view: str) -> None:
        self.view, self.extra, self.show_log = view, "", False
        self.render_view(reset=True)
        self.query_one("#peers" if view == "builders" else "#table", DataTable).focus()

    async def action_toggle_log(self) -> None:
        if self.view != "detail" or None in (self.detail_id, self.peers, self.node_id):
            return
        self.show_log = not self.show_log
        self.extra = (
            await poll_log(self.peers, self.node_id, self.detail_id) if self.show_log else ""
        )
        self.render_view()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "table":
            return
        key = event.row_key.value
        if self.view in ("builders", "releases", "detail") and key:
            self.view, self.detail_id, self.show_log, self.extra = "detail", key, False, ""
            self.render_view()
        elif self.view == "evidence" and key is not None:
            item = self.evidence[int(key)] if int(key) < len(self.evidence) else None
            if item is not None:
                ok = "valid" if check_proof(item, self.g) else "unverified"
                self.extra = f"proof ({ok}):\n" + json.dumps(item.get("proof"), indent=2)
                self.render_view()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "table" and self.view != "evidence" and event.row_key:
            self.detail_id = event.row_key.value
            self._update_detail()

    def on_resize(self) -> None:
        if self.query("#divider"):
            self._render_divider()

    # rendering

    def render_view(self, reset: bool = False) -> None:
        peers = self.query_one("#peers", DataTable)
        table = self.query_one("#table", DataTable)
        row = 0 if reset else table.cursor_row
        peers.clear(columns=True)
        table.clear(columns=True)
        self._render_builders(peers)
        if self.view == "evidence":
            self.query_one("#requests-title", Static).update("EVIDENCE")
            self._render_evidence(table)
        else:
            self.query_one("#requests-title", Static).update("REQUESTS")
            self._render_releases(table)
        online = sum(self._online(n.id) for n in self.g.nodes)
        self.query_one("#peers-title", Static).update(
            f"PEERS ({len(self.g.nodes)}) · {online} online"
        )
        node = self.g.node(self.node_id) if self.node_id else None
        self.query_one("#dashboard", Vertical).border_title = (
            f"MATRIX · {node.operator} · {node.id}"
            if node
            else f"MATRIX · no builder at {self.local} (start `matrix up`, or pass --node)"
        )
        if table.row_count:
            table.move_cursor(row=min(row, table.row_count - 1))
        self._update_detail()
        self._render_divider()

    def _render_divider(self) -> None:
        width = self.query_one("#divider", Static).size.width
        split = self.query_one("#peers-panel", Vertical).size.width
        self.query_one("#divider", Static).update(_divider(width, split))

    def _online(self, node_id: str) -> bool:
        # With hellos (a founded network), online means a fresh signed hello; with static dev
        # addresses, that /v1/health answered. Offline members stay listed: disconnect != leave.
        if self.book is not None and self.book.peers_now is not None:
            return self.book.online(node_id)
        return self.health.get(node_id) is not None

    def _address(self, node: Any) -> str:
        hello = AddressBook.addr(self.book, node.id) if self.book is not None else None
        return hello or node.addr or "-"  # the LAN address from its hello, not the loopback

    def _render_builders(self, t: DataTable) -> None:
        t.add_columns("node", "operator", "status", "genesis", "address")
        for n in sorted(self.g.nodes, key=lambda n: n.operator):
            h = self.health.get(n.id)
            up = self._online(n.id)
            match = (
                h is not None and h.get("genesis_hash") == self.g.hash and h.get("node_id") == n.id
            )
            t.add_row(
                n.id,
                n.operator,
                _styled("● UP" if up else "○ DOWN", "green" if up else "red"),
                _styled(
                    "✓" if match else "?" if h is None else "!", "green" if match else "yellow"
                ),
                _styled(self._address(n), "muted"),
                key=n.id,
            )

    def _render_releases(self, t: DataTable) -> None:
        t.add_columns("request", "attested", "quorum", "verdict")
        for r in self.releases:
            att, top = r.counts()
            name = f"{r.body['repo_url'].rsplit('/', 1)[-1]}@{r.body['tag']}" if r.body else "?"
            request = Text.assemble(
                (r.id[:8], _COLORS["muted"]),
                (f"  {name}", _COLORS["text"]),
                (f"\n{r.phase}", _COLORS["muted"]),
            )
            t.add_row(
                request,
                _styled(f"{att}/{self.g.replicas}", "yellow" if att < self.g.replicas else "green"),
                _styled(
                    f"{min(top, self.g.threshold)}/{self.g.threshold}",
                    "green" if top >= self.g.threshold else "yellow",
                ),
                _verdict_text(r.verdict),
                height=2,
                key=r.id,
            )

    def _update_detail(self) -> None:
        r = next((r for r in self.releases if r.id == self.detail_id), None)
        if r is None:
            r = self.releases[0] if self.releases else None
            self.detail_id = r.id if r else None
        self.query_one("#details-title", Static).update(
            f"REQUEST DETAILS · {r.id[:8]}" if r else "REQUEST DETAILS"
        )
        self.query_one("#details", Static).update(
            self._render_detail(r) if r else _styled("No requests on this node", "muted")
        )
        self.query_one("#extra", Static).update(Text(self.extra))

    def _render_detail(self, r: Release) -> Text:
        lines = Text()
        matched = 0
        for nid, _, res, mark in builder_rows(self.g, r.id, r.verdict):
            if mark == "ok":
                label, colour = "MATCH", "green"
                matched += 1
            elif mark == "DISAGREE":
                label, colour = "DISAGREES", "red"
            elif mark == "EQUIVOCATION":
                label, colour = "EQUIVOCATION", "red"
            elif res == "-":
                label, colour = "NO ATTESTATION", "yellow"
            else:
                label, colour = "PENDING", "yellow"
            state = "--" if res == "-" else "FAILED" if res == "FAILED" else "ATTESTED"
            result = "--" if res == "-" else res[:12] + ("…" if len(res) > 12 else "")
            lines.append_text(_styled(f"{nid:<12} {state:<10} {result:<16} {label}\n", colour))
        state = _verdict_text(r.verdict)
        verdict = Text.assemble(
            ("VERDICT: ", _COLORS["blue"]),
            (state.plain, state.style),
            (
                f" · {matched}/{self.g.replicas} MATCHED · THRESHOLD: {self.g.threshold}",
                _COLORS["muted"],
            ),
        )
        lines.append_text(verdict)
        return lines

    def _render_evidence(self, t: DataTable) -> str:
        t.add_columns("kind", "signer", "release", "time", "proof")
        names = {r.id: f"{r.body['tag']} ({r.id[:8]})" for r in self.releases if r.body}
        for i, e in enumerate(self.evidence):
            ok = check_proof(e, self.g)
            proof = Text(
                "valid" if ok else "unverified",
                _COLORS["green"] if ok else _COLORS["yellow"],
            )
            t.add_row(
                Text(e["kind"], _COLORS["red"]),
                e["signer"],
                names.get(e["request_id"], e["request_id"][:12]),
                Text(_time(e.get("created_at")), _COLORS["muted"]),
                proof,
                key=str(i),
            )
        return "Enter: proof JSON"


def run_tui(g: Genesis, local: str) -> int:
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            curses.wrapper(_intro)  # wrapper restores terminal modes before Textual starts.
        except (curses.error, OSError):
            pass  # A terminal without curses support can still run the dashboard.
    MatrixTui(g, local).run()
    return 0


def main() -> None:
    from .cli import run

    sys.exit(run(["tui", *sys.argv[1:]]))
