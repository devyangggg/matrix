"""Start eight real local matrix-node processes with disposable identities and data."""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

from aiohttp import ClientError, ClientSession, ClientTimeout

ROOT = Path(__file__).resolve().parents[2]
IMAGE = os.environ.get("MATRIX_TEST_IMAGE", "")
REPO = os.environ.get("MATRIX_TEST_REPO", "")


class Network:
    def __init__(
        self,
        directory: Path,
        faults: dict[str, list[str]] | None = None,
        offline: set[str] | None = None,
    ):
        self.directory = directory
        self.faults = faults or {}
        self.offline = offline or set()
        self.processes: dict[str, asyncio.subprocess.Process] = {}
        self.logs = []
        self.genesis = None
        self.session = None

    async def __aenter__(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        generator = await asyncio.create_subprocess_exec(
            sys.executable,
            str(ROOT / "scripts" / "dev_genesis.py"),
            "--out",
            str(self.directory / "dev"),
            "--addrs",
            "local",
            "--profile",
            "demo",
            "--repo",
            REPO,
            "--image",
            IMAGE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, error = await generator.communicate()
        if generator.returncode:
            raise RuntimeError(f"dev genesis failed: {error.decode(errors='replace')}")
        self.genesis = json.loads((self.directory / "dev" / "genesis.json").read_text())
        self.session = ClientSession(timeout=ClientTimeout(total=2))
        try:
            for index in range(1, 9):
                node_id = f"builder{index}"
                if node_id in self.offline:
                    continue
                logfile = (self.directory / f"{node_id}.log").open("wb")
                self.logs.append(logfile)
                command = [
                    sys.executable,
                    "-m",
                    "matrix.node",
                    "--genesis",
                    str(self.directory / "dev" / "genesis.json"),
                    "--id",
                    node_id,
                    "--key",
                    str(self.directory / "dev" / "keys" / f"{node_id}.key"),
                    "--listen",
                    f"127.0.0.1:{7699 + index}",
                    "--data",
                    str(self.directory / node_id),
                ]
                if node_id in self.faults:
                    command += ["--allow-faults", *self.faults[node_id]]
                self.processes[node_id] = await asyncio.create_subprocess_exec(
                    *command, stdout=logfile, stderr=asyncio.subprocess.STDOUT, cwd=ROOT
                )
            for node_id in self.processes:
                await self.wait_health(node_id)
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def wait_health(self, node_id: str) -> None:
        deadline = time.monotonic() + 25
        url = f"http://{self.address(node_id)}/v1/health"
        while time.monotonic() < deadline:
            if self.processes[node_id].returncode is not None:
                raise RuntimeError(
                    f"{node_id} exited early; see {self.directory / (node_id + '.log')}"
                )
            try:
                async with self.session.get(url) as response:
                    data = await response.json()
                    expected = (self.directory / "dev" / "genesis.sha256").read_text().strip()
                    if (
                        response.status == 200
                        and data["node_id"] == node_id
                        and data["genesis_hash"] == expected
                    ):
                        return
            except (ClientError, OSError, TimeoutError):
                pass
            await asyncio.sleep(0.1)
        raise TimeoutError(
            f"{node_id} health unavailable; see {self.directory / (node_id + '.log')}"
        )

    def address(self, node_id: str) -> str:
        return next(node["addr"] for node in self.genesis["nodes"] if node["id"] == node_id)

    async def post(self, node_id: str, path: str, envelope: dict) -> int:
        async with self.session.post(
            f"http://{self.address(node_id)}{path}", json=envelope
        ) as response:
            await response.read()
            return response.status

    async def bundle(self, node_id: str, rid: str) -> dict | None:
        try:
            async with self.session.get(
                f"http://{self.address(node_id)}/v1/requests/{rid}/bundle"
            ) as response:
                return await response.json() if response.status == 200 else None
        except (ClientError, OSError, TimeoutError):
            return None

    async def __aexit__(self, _type, _value, _traceback):
        for proc in self.processes.values():
            if proc.returncode is None:
                proc.terminate()
        for proc in self.processes.values():
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        if self.session:
            await self.session.close()
        for logfile in self.logs:
            logfile.close()
