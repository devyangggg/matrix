"""Opt-in fault behaviors for a builder node."""

import os
import secrets
from dataclasses import dataclass


@dataclass
class Fault:
    mode: str | None = None
    patch: str | None = None
    hash: str | None = None

    def on_new_request(self) -> None:
        if self.mode == "crash":
            os._exit(1)

    def attest_without_build(self) -> str | None:
        if self.mode == "lie":
            return secrets.token_hex(32)
        if self.mode == "collude":
            return self.hash
        if self.mode == "stall":
            return "STALL"
        return None

    @property
    def corrupt_artifacts(self) -> bool:
        return self.mode == "bad-artifact"
