"""Tests for the opt-in fault behaviors."""

import re

import pytest

from matrix.faults import Fault


def test_default_fault_is_inert(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_exit(code: int) -> None:
        pytest.fail(f"unexpected exit with code {code}")

    monkeypatch.setattr("matrix.faults.os._exit", unexpected_exit)
    fault = Fault()
    fault.on_new_request()
    assert fault.attest_without_build() is None
    assert fault.corrupt_artifacts is False
    assert fault.patch is None
    assert fault.hash is None


@pytest.mark.parametrize(
    "mode", ["inject", "lie", "collude", "stall", "equivocate", "bad-artifact"]
)
def test_non_crash_modes_do_not_exit(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_exit(code: int) -> None:
        pytest.fail(f"unexpected exit with code {code}")

    monkeypatch.setattr("matrix.faults.os._exit", unexpected_exit)
    Fault(mode=mode).on_new_request()


def test_crash_exits_with_status_one(monkeypatch: pytest.MonkeyPatch) -> None:
    exits: list[int] = []
    monkeypatch.setattr("matrix.faults.os._exit", exits.append)
    Fault(mode="crash").on_new_request()
    assert exits == [1]


def test_lie_produces_random_sha256_hex() -> None:
    fault = Fault(mode="lie")
    first = fault.attest_without_build()
    second = fault.attest_without_build()
    assert first is not None and re.fullmatch(r"[0-9a-f]{64}", first)
    assert second is not None and re.fullmatch(r"[0-9a-f]{64}", second)
    assert first != second


def test_collude_uses_supplied_hash() -> None:
    digest = "ab" * 32
    assert Fault(mode="collude", hash=digest).attest_without_build() == digest


def test_stall_returns_sentinel() -> None:
    assert Fault(mode="stall").attest_without_build() == "STALL"


@pytest.mark.parametrize("mode", ["inject", "crash", "equivocate", "bad-artifact"])
def test_other_modes_do_not_attest_without_build(mode: str) -> None:
    assert Fault(mode=mode).attest_without_build() is None


def test_only_bad_artifact_corrupts_artifacts() -> None:
    assert Fault(mode="bad-artifact").corrupt_artifacts is True
    for mode in (None, "inject", "lie", "collude", "stall", "crash", "equivocate"):
        assert Fault(mode=mode).corrupt_artifacts is False


def test_inject_patch_is_carried_without_autonomous_action() -> None:
    fault = Fault(mode="inject", patch="patch.diff")
    assert fault.patch == "patch.diff"
    assert fault.attest_without_build() is None
