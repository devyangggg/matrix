"""Textual TUI: Builders, Releases, Detail, Evidence (RFC §7.12, LLD §3.14).

Talks to builders over the HTTP API only and never opens the database. Every second it polls
the chosen node and each builder's /v1/health, runs verdict() locally on what it fetched, and
keeps nothing beyond the last poll result.
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

_COLORS = {
    "background": "#11111B",
    "panel": "#1D1B2A",
    "text": "#EDE9F5",
    "muted": "#9995AC",
    "purple": "#C4B5FD",
    "green": "#7DD3C0",
    "yellow": "#E6B86B",
    "red": "#D68198",
    "border": "#353246",
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
        return dict.fromkeys(("purple", "green", "muted", "fade1", "fade2", "text"), 0)
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
    )
    for pair, (indexed, basic) in enumerate(palette, 1):
        curses.init_pair(pair, indexed if curses.COLORS >= 256 else basic, background)
    return dict(
        zip(
            ("purple", "green", "muted", "fade1", "fade2", "text"),
            (curses.color_pair(i) for i in range(1, 7)),
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
        _put(win, rows // 2, max(0, (cols - len(label)) // 2), label, colors["purple"])
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
            attr = colors["purple"]
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
    return "(no log on this builder)" if data is None else data.decode("utf-8", "replace")


def _time(t: object) -> str:
    if not isinstance(t, (int, float)) or not 0 <= t < 1e11:
        return "-"
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _verdict_text(v: Verdict) -> Text:
    style = {"AGREED": _COLORS["green"], "PENDING": _COLORS["yellow"]}.get(v.state, _COLORS["red"])
    label = f"AGREED {v.hash[:12]}" if v.state == "AGREED" else v.state
    return Text(label, style=style)


# the app


class MatrixTui(App):
    TITLE = "MATRIX"
    CSS = f"""
    Screen {{
        background: {_COLORS["background"]};
        color: {_COLORS["text"]};
    }}
    Header {{
        background: {_COLORS["panel"]};
        color: {_COLORS["purple"]};
    }}
    #status {{
        height: 3;
        padding: 0 1;
        background: {_COLORS["panel"]};
        border: round {_COLORS["border"]};
    }}
    DataTable {{
        height: 1fr;
        background: {_COLORS["panel"]};
        color: {_COLORS["text"]};
        border: round {_COLORS["border"]};
    }}
    DataTable:focus {{
        border: round {_COLORS["purple"]};
    }}
    #extra {{
        height: auto;
        max-height: 35%;
        overflow-y: auto;
        background: {_COLORS["panel"]};
        color: {_COLORS["muted"]};
        border: round {_COLORS["border"]};
    }}
    Footer {{
        background: {_COLORS["panel"]};
        color: {_COLORS["muted"]};
    }}
    FooterKey .footer-key--key {{
        color: {_COLORS["purple"]};
        background: {_COLORS["panel"]};
    }}
    FooterKey .footer-key--description {{
        color: {_COLORS["muted"]};
        background: {_COLORS["panel"]};
    }}
    """
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
        healthy = sum(
            1
            for n in self.g.nodes
            if (h := self.health.get(n.id)) is not None
            and h.get("genesis_hash") == self.g.hash
            and h.get("node_id") == n.id
        )
        connection = (
            _COLORS["green"]
            if healthy == len(self.g.nodes)
            else _COLORS["yellow"]
            if reachable
            else _COLORS["red"]
        )
        summary = Text.assemble(
            (self.view.upper(), f"bold {_COLORS['purple']}"),
            (f"  │  node {self.node_id}  │  ", _COLORS["muted"]),
            (f"builders up {reachable}/{len(self.g.nodes)}", connection),
            (f"  │  {status}", _COLORS["muted"]),
        )
        self.query_one("#status", Static).update(summary)
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
                Text("yes", _COLORS["green"]) if h else Text("no", _COLORS["red"]),
                Text(
                    "match" if match else "-" if h is None else "MISMATCH",
                    _COLORS["green"]
                    if match
                    else _COLORS["muted"]
                    if h is None
                    else _COLORS["yellow"],
                ),
                Text(_time(h.get("now")) if h else "-", _COLORS["muted"]),
            )
        return f"genesis {self.g.hash[:16]}"

    def _render_releases(self, t: DataTable) -> str:
        t.add_columns("id", "release", "phase", "attested", "quorum", "verdict")
        for r in self.releases:
            att, top = r.counts()
            name = f"{r.body['repo_url'].rsplit('/', 1)[-1]}@{r.body['tag']}" if r.body else "?"
            t.add_row(
                Text(r.id[:12], _COLORS["muted"]),
                Text(name, _COLORS["purple"]),
                Text(r.phase, _COLORS["muted"]),
                f"{att}/{self.g.replicas}",
                Text(
                    f"{min(top, self.g.threshold)}/{self.g.threshold}",
                    _COLORS["green"] if top >= self.g.threshold else _COLORS["yellow"],
                ),
                _verdict_text(r.verdict),
                key=r.id,
            )
        return "Enter: detail"

    def _render_detail(self, t: DataTable) -> str:
        t.add_columns("builder", "operator", "result", "matches quorum")
        r = next((r for r in self.releases if r.id == self.detail_id), None)
        if r is None:
            return f"release {self.detail_id or '?'} not on this node"
        style = {
            "ok": _COLORS["green"],
            "DISAGREE": _COLORS["red"],
            "EQUIVOCATION": _COLORS["red"],
        }
        for nid, op, res, mark in builder_rows(self.g, r.id, r.verdict):
            colour = style.get(mark, _COLORS["yellow"])
            t.add_row(nid, op, Text(res, colour), Text(mark or "-", colour))
        name = f"{r.body['repo_url']}@{r.body['tag']}" if r.body else "?"
        return f"{name}  " + _verdict_text(r.verdict).plain + "  l: log tail"

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


def run_tui(g: Genesis, node_id: str) -> int:
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            curses.wrapper(_intro)  # wrapper restores terminal modes before Textual starts.
        except (curses.error, OSError):
            pass  # A terminal without curses support can still run the dashboard.
    MatrixTui(g, node_id).run()
    return 0


def main() -> None:
    from .cli import run

    sys.exit(run(["tui", *sys.argv[1:]]))
