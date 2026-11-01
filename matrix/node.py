"""Builder daemon entry point: validate identity, recover, then serve the mesh."""

import argparse
import asyncio
import logging
import os
import re
import signal
import sys
import time
from pathlib import Path

from aiohttp import web

from matrix.faults import Fault
from matrix.net import PeerClient, make_app

log = logging.getLogger(__name__)
_MODES = ("inject", "lie", "collude", "stall", "crash", "equivocate", "bad-artifact")


def configure_logging(verbose: bool, file: str | None = None) -> None:
    """--verbose: every step at DEBUG on stderr (or in `file`, for the full-screen TUI)."""
    if not verbose:
        return
    handler = logging.FileHandler(file) if file else logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)-5s %(name)s: %(message)s", "%H:%M:%S"
        )
    )
    logging.basicConfig(level=logging.DEBUG, handlers=[handler], force=True)
    logging.getLogger("asyncio").setLevel(logging.INFO)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Matrix builder daemon")
    parser.add_argument("--genesis", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--advertise", help="address put in hellos, <IPv4>:<port>")
    parser.add_argument(
        "--no-discovery", action="store_true", help="no hellos; reach peers by genesis addr only"
    )
    parser.add_argument("--allow-faults", action="store_true")
    parser.add_argument("--fault", choices=_MODES)
    parser.add_argument("--patch")
    parser.add_argument("--hash")
    parser.add_argument("--verbose", "-v", action="store_true", help="log every step to stderr")
    return parser


def _fault(args: argparse.Namespace) -> Fault:
    if (args.fault or args.patch or args.hash) and not args.allow_faults:
        raise ValueError("fault flags require --allow-faults")
    if args.patch and args.fault != "inject":
        raise ValueError("--patch requires --fault inject")
    if args.hash and args.fault != "collude":
        raise ValueError("--hash requires --fault collude")
    if args.fault == "inject" and (not args.patch or not Path(args.patch).is_file()):
        raise ValueError("inject requires a readable --patch FILE")
    if args.fault == "collude" and (
        not args.hash or re.fullmatch(r"[0-9a-f]{64}", args.hash, re.ASCII) is None
    ):
        raise ValueError("collude requires a 64-character lowercase hex --hash")
    return Fault(mode=args.fault, patch=args.patch, hash=args.hash)


def _listen(address: str) -> tuple[str, int]:
    host, separator, port_text = address.rpartition(":")
    if not separator or not host or re.fullmatch(r"[0-9]{1,5}", port_text, re.ASCII) is None:
        raise ValueError("--listen must be HOST:PORT")
    port = int(port_text)
    if not 0 < port < 65536:
        raise ValueError("--listen port out of range")
    return host, port


async def run(args: argparse.Namespace) -> None:
    from matrix.discovery import AddressBook, Discovery, valid_addr

    fault = _fault(args)
    host, port = _listen(args.listen)
    advertise = getattr(args, "advertise", None)
    discovery = not getattr(args, "no_discovery", False)
    if advertise is not None and not valid_addr(advertise):
        raise ValueError("--advertise must be <IPv4>:<port>")
    from matrix.builder import BuildEnv, cleanup_startup, expire_artifacts, isolation
    from matrix.crypto import load_key, pubkey_hex
    from matrix.genesis import load_genesis
    from matrix.protocol import Engine
    from matrix.store import Store

    log.info(
        "node: listen=%s:%d advertise=%s discovery=%s fault=%s",
        host,
        port,
        advertise or "auto",
        discovery,
        fault.mode,
    )
    g = load_genesis(args.genesis)
    log.info(
        "node: genesis %s loaded: %d nodes, f=%d, threshold=%d, hash %s",
        args.genesis,
        len(g.nodes),
        g.f,
        g.threshold,
        g.hash,
    )
    me = g.node(args.id)
    if me is None:
        raise ValueError("node id is not in genesis")
    sk = load_key(args.key)
    if pubkey_hex(sk) != me.pubkey:
        raise ValueError("node key does not match genesis")
    log.info("node: identity %s, key %s matches genesis", me.id, args.key)
    data_dir = Path(args.data).resolve()
    for subdir in ("work", "logs", "artifacts"):
        (data_dir / subdir).mkdir(parents=True, exist_ok=True)
    log.info("node: data dir %s (work, logs, artifacts ready)", data_dir)
    runtime, how = await isolation()
    log.info("%s build isolation: %s", me.id, how)
    env = BuildEnv(str(data_dir), me.id, os.getuid(), os.getgid(), runtime)
    store = Store(str(data_dir / "matrix.db"))
    log.info("node: store opened %s", data_dir / "matrix.db")
    book = AddressBook(g)
    peers = PeerClient(g, me, book)
    runner = None
    tasks = []
    stop_waiter = None
    try:
        await cleanup_startup(env)
        expire_artifacts(env, time.time())
        log.info("node: startup cleanup done (stale containers, work dirs, old artifacts)")
        engine = Engine(g, me, sk, store, peers, env, fault)
        await engine.recover()
        log.info("node: recovery done")
        runner = web.AppRunner(make_app(engine, store, g, me, env, book))
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        log.info("node: HTTP API serving on %s:%d", host, port)
        tasks = [
            asyncio.create_task(engine.build_worker()),
            asyncio.create_task(engine.sync_loop()),
        ]
        log.info("node: build worker and sync loop started")
        if discovery:  # a bind failure ends this task and the node stops (RFC §7.15)
            tasks.append(asyncio.create_task(Discovery(g, me, sk, book, port, advertise).run()))
        else:
            log.info("node: discovery off (--no-discovery): peers come from genesis addr only")
        log.info("%s listening at %s:%d", me.id, host, port)
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stopped.set)
        stop_waiter = asyncio.create_task(stopped.wait())
        done, _ = await asyncio.wait([*tasks, stop_waiter], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if task is not stop_waiter:
                task.result()
                raise RuntimeError("builder worker stopped unexpectedly")
        log.info("node: stop signal received, shutting down")
    finally:
        if stop_waiter is not None:
            stop_waiter.cancel()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if runner is not None:
            await runner.cleanup()
        await peers.close()
        log.info("node: stopped")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    configure_logging(args.verbose)
    try:
        asyncio.run(run(args))
    except ValueError as exc:
        print(f"matrix-node: {exc}", file=sys.stderr)
        return 2
    except Exception:
        logging.getLogger(__name__).exception("matrix-node startup failed")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
