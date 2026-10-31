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

_MODES = ("inject", "lie", "collude", "stall", "crash", "equivocate", "bad-artifact")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Matrix builder daemon")
    parser.add_argument("--genesis", required=True)
    parser.add_argument("--id", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--allow-faults", action="store_true")
    parser.add_argument("--fault", choices=_MODES)
    parser.add_argument("--patch")
    parser.add_argument("--hash")
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
    if (
        not separator
        or not host
        or re.fullmatch(r"[0-9]{1,5}", port_text, re.ASCII) is None
    ):
        raise ValueError("--listen must be HOST:PORT")
    port = int(port_text)
    if not 0 < port < 65536:
        raise ValueError("--listen port out of range")
    return host, port


async def run(args: argparse.Namespace) -> None:
    fault = _fault(args)
    host, port = _listen(args.listen)
    from matrix.builder import BuildEnv, cleanup_startup, expire_artifacts
    from matrix.crypto import load_key, pubkey_hex
    from matrix.genesis import load_genesis
    from matrix.protocol import Engine
    from matrix.store import Store

    g = load_genesis(args.genesis)
    me = g.node(args.id)
    if me is None:
        raise ValueError("node id is not in genesis")
    sk = load_key(args.key)
    if pubkey_hex(sk) != me.pubkey:
        raise ValueError("node key does not match genesis")
    data_dir = Path(args.data).resolve()
    for subdir in ("work", "logs", "artifacts"):
        (data_dir / subdir).mkdir(parents=True, exist_ok=True)
    env = BuildEnv(str(data_dir), me.id, os.getuid(), os.getgid())
    store = Store(str(data_dir / "matrix.db"))
    peers = PeerClient(g, me)
    runner = None
    tasks = []
    stop_waiter = None
    try:
        await cleanup_startup(env)
        expire_artifacts(env, time.time())
        engine = Engine(g, me, sk, store, peers, env, fault)
        await engine.recover()
        runner = web.AppRunner(make_app(engine, store, g, me, env))
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        tasks = [
            asyncio.create_task(engine.build_worker()),
            asyncio.create_task(engine.sync_loop()),
        ]
        logging.getLogger(__name__).info("%s listening at %s:%d", me.id, host, port)
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stopped.set)
        stop_waiter = asyncio.create_task(stopped.wait())
        done, _ = await asyncio.wait(
            [*tasks, stop_waiter], return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            if task is not stop_waiter:
                task.result()
                raise RuntimeError("builder worker stopped unexpectedly")
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


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
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
