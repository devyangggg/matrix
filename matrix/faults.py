from dataclasses import dataclass


@dataclass
class Fault:
    mode: str | None = None  # None|inject|lie|collude|stall|crash|equivocate|bad-artifact
    patch: str | None = None  # inject
    hash: str | None = None  # collude

    def on_new_request(self) -> None:
        raise NotImplementedError

    def attest_without_build(self) -> str | None:
        raise NotImplementedError

    @property
    def corrupt_artifacts(self) -> bool:
        raise NotImplementedError
