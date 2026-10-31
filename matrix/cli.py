"""Matrix client entrypoint; launch the read-only TUI against a trusted genesis."""

import argparse
import os
import sys
from pathlib import Path

from .genesis import GenesisError, load_genesis


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="matrix")
    parser.add_argument("--genesis", dest="root_genesis")
    commands = parser.add_subparsers(dest="command", required=True)
    tui = commands.add_parser("tui", help="view builders, releases and evidence")
    tui.add_argument("--genesis")
    tui.add_argument("--node", help="builder ID (default: first node in genesis)")
    args = parser.parse_args(argv)

    path = args.genesis or args.root_genesis or os.environ.get("MATRIX_GENESIS")
    if path is None:
        path = str(Path.home() / ".matrix" / "genesis.json")
    try:
        genesis = load_genesis(path)
    except (GenesisError, ValueError) as exc:
        print(f"matrix: {exc}", file=sys.stderr)
        return 4
    node = genesis.node(args.node) if args.node else genesis.nodes[0]
    if node is None:
        print(f"matrix: unknown builder {args.node}", file=sys.stderr)
        return 4
    from .tui import run_tui

    run_tui(genesis, node)
    return 0
