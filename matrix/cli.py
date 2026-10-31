"""`matrix` CLI: keygen, release, status, verify, evidence, tui (RFC §7.11, LLD §3.13)."""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

from .crypto import keygen
from .genesis import GenesisError, load_genesis
from .model import parse_certificate, parse_envelope
from .verdict import verdict

RELEASE_POLL_S = 2

EXIT_OK = 0
EXIT_MISMATCH = 1  # verify
EXIT_INVALID = 2  # verify: INVALID_CERT; release: NOT_REPRODUCIBLE
EXIT_PENDING = 3
EXIT_ERROR = 4
EXIT_BUILD_FAILED = 5

_HEX64 = re.compile(r"[0-9a-f]{64}", re.ASCII)


def _out(msg: str) -> None:
    print(msg, flush=True)


def _err(msg: str) -> None:
    print(f"matrix: {msg}", file=sys.stderr, flush=True)


def _genesis_path(arg: str | None) -> str:
    # LLD L9: --genesis, then $MATRIX_GENESIS, then ~/.matrix/genesis.json
    return arg or os.environ.get("MATRIX_GENESIS") or str(Path.home() / ".matrix" / "genesis.json")


def _read_pin(arg: str | None) -> str | None:
    """The pinned genesis hash: --genesis-sha256, else ~/.matrix/genesis.sha256 (LLD §4)."""
    if arg is not None:
        text = arg
    else:
        try:
            text = (Path.home() / ".matrix" / "genesis.sha256").read_text("ascii")
        except (OSError, UnicodeDecodeError):
            return None
    pin = text.removesuffix("\n")
    return pin if _HEX64.fullmatch(pin) else None


# keygen


def cmd_keygen(a: argparse.Namespace) -> int:
    seed, pub = keygen()
    try:
        # O_EXCL: never overwrite an existing key; 0600: the seed is a secret (LLD §4).
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(seed + "\n")
    except OSError as e:
        _err(f"cannot write key file: {e}")
        return EXIT_ERROR
    _out(pub)
    return EXIT_OK


# verify (offline: this function never opens a socket)


def cmd_verify(a: argparse.Namespace) -> int:
    try:
        data = Path(a.file).read_bytes()
        cert_raw = Path(a.cert).read_bytes()
        g = load_genesis(_genesis_path(a.genesis))
    except (OSError, GenesisError) as e:
        _err(str(e))
        return EXIT_ERROR
    pin = _read_pin(a.genesis_sha256)
    if pin is None:
        _err("no valid pinned genesis hash (--genesis-sha256 or ~/.matrix/genesis.sha256)")
        return EXIT_ERROR
    if g.hash != pin:
        _err("genesis file does not match the pinned hash")
        return EXIT_ERROR

    def invalid(why: str) -> int:
        _out(f"INVALID_CERT: {why}")
        return EXIT_INVALID

    c = parse_certificate(cert_raw, g)
    if c is None:
        return invalid("malformed certificate")
    if c.genesis_hash != pin:
        return invalid("certificate is for a different genesis")
    req = parse_envelope(c.request, g)
    if req is None or req.type != "release":
        return invalid("request is not signed by a genesis release signer")
    if req.body["repo_url"] != a.repo or req.body["tag"] != a.tag:
        return invalid(f"certificate is for {req.body['repo_url']}@{req.body['tag']}")
    if a.commit is not None and req.body["commit"] != a.commit:
        return invalid(f"certificate is for commit {req.body['commit']}")
    # Invariant 4: the request comes from the caller-checked certificate, not from attestations.
    v = verdict(c.request, c.attestations, g)
    if v.state != "AGREED":
        return invalid(f"attestations give {v.state}, not AGREED")
    if hashlib.sha256(data).hexdigest() != v.hash:
        _out(f"MISMATCH: file sha256 differs from the certified {v.hash}")
        return EXIT_MISMATCH
    _out(f"REPRODUCED {v.hash} {a.repo}@{a.tag}")
    return EXIT_OK


# entry point


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="matrix", description="Matrix release gate")
    p.add_argument("--genesis", help="genesis.json (default $MATRIX_GENESIS or ~/.matrix/)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("keygen", help="generate an Ed25519 key; prints the public key")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_keygen)

    s = sub.add_parser("verify", help="check a binary against its certificate, offline")
    s.add_argument("file")
    s.add_argument("--cert", required=True)
    s.add_argument("--repo", required=True)
    s.add_argument("--tag", required=True)
    s.add_argument("--commit")
    s.add_argument("--genesis-sha256", help="pinned genesis hash (default ~/.matrix/)")
    s.set_defaults(fn=cmd_verify)
    return p


def run(argv: list[str] | None = None) -> int:
    p = _parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:  # argparse exits 2 on bad usage; 2 means INVALID here, so remap
        return EXIT_OK if e.code == 0 else EXIT_ERROR
    try:
        return a.fn(a)
    except Exception as e:  # noqa: BLE001  fail closed: an unexpected error is never success
        _err(f"unexpected error: {e!r}")
        return EXIT_ERROR


def main() -> None:
    sys.exit(run())
