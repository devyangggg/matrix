"""`matrix verify`: RFC §6.4 verify rows, RFC §7.11 verify steps, LLD §11."""

import hashlib
import json
import os
import socket
import stat
from types import SimpleNamespace

import pytest
from conftest import COMMIT, REPO, genesis_raw

from matrix.canon import canonical_json
from matrix.cli import run
from matrix.crypto import load_key, pubkey_hex
from matrix.genesis import parse_genesis
from matrix.model import make_envelope

BINARY = b"\x7fELF honest binary"
H = hashlib.sha256(BINARY).hexdigest()


@pytest.fixture(autouse=True)
def no_network_home(tmp_path, monkeypatch):
    """verify must never open a socket; and must not read the developer's real ~/.matrix."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MATRIX_GENESIS", raising=False)

    def refuse(*a, **k):
        raise AssertionError("verify opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def files(tmp_path, genesis, release_env, attest):
    """Writes genesis, binary and a valid certificate; returns a helper to run verify."""
    gpath = tmp_path / "genesis.json"
    gpath.write_bytes(canonical_json(genesis_raw()))
    binary = tmp_path / "hello"
    binary.write_bytes(BINARY)
    cert = tmp_path / "hello.matrix.json"

    def write_cert(request=release_env, atts=None, genesis_hash=genesis.hash, raw=None):
        if atts is None:
            atts = [attest(s, H) for s in ("builder1", "builder2", "builder3")]
        doc = {"v": 1, "genesis_hash": genesis_hash, "request": request, "attestations": atts}
        cert.write_bytes(raw if raw is not None else canonical_json(doc))

    def verify(*extra, pin=genesis.hash, repo=REPO, tag="v1.2.0", file=binary):
        args = ["--genesis", str(gpath), "verify", str(file), "--cert", str(cert)]
        args += ["--repo", repo, "--tag", tag]
        if pin is not None:
            args += ["--genesis-sha256", pin]
        return run(args + list(extra))

    write_cert()
    return SimpleNamespace(
        write_cert=write_cert, verify=verify, binary=binary, gpath=gpath, tmp=tmp_path
    )


def test_reproduced(files):
    assert files.verify() == 0


def test_reproduced_with_commit(files):
    assert files.verify("--commit", COMMIT) == 0


def test_pin_from_home_file(files, genesis):
    (files.tmp / ".matrix").mkdir()
    (files.tmp / ".matrix" / "genesis.sha256").write_text(genesis.hash + "\n")
    assert files.verify(pin=None) == 0


def test_genesis_from_env(files, genesis, monkeypatch):
    monkeypatch.setenv("MATRIX_GENESIS", str(files.gpath))
    args = ["verify", str(files.binary), "--cert", str(files.tmp / "hello.matrix.json")]
    assert run(args + ["--repo", REPO, "--tag", "v1.2.0", "--genesis-sha256", genesis.hash]) == 0


def test_swapped_binary_is_mismatch(files):
    files.binary.write_bytes(b"backdoored binary")
    assert files.verify() == 1


# exit 2: INVALID_CERT


def test_wrong_repo(files):
    assert files.verify(repo="https://github.com/org/other") == 2


def test_wrong_tag_older_certificate(files):
    assert files.verify(tag="v1.2.1") == 2  # demo scene 4: an older release's certificate


def test_wrong_commit(files):
    assert files.verify("--commit", "2" * 40) == 2


def test_too_few_attestations(files, attest):
    files.write_cert(atts=[attest("builder1", H), attest("builder2", H)])
    assert files.verify() == 2


def test_duplicated_attestations_count_once(files, attest):
    a = attest("builder1", H)
    files.write_cert(atts=[a, a, a, attest("builder2", H)])
    assert files.verify() == 2


def test_equivocator_not_counted(files, attest):
    atts = [attest(s, H) for s in ("builder1", "builder2", "builder3")]
    files.write_cert(atts=atts + [attest("builder3", "f" * 64)])
    assert files.verify() == 2


def test_failed_quorum_is_invalid(files, attest):
    files.write_cert(atts=[attest(s, "FAILED") for s in ("builder1", "builder2", "builder3")])
    assert files.verify() == 2


def test_attestations_for_another_request_ignored(files, attest):
    other = "e" * 64
    files.write_cert(atts=[attest(s, H, other) for s in ("builder1", "builder2", "builder3")])
    assert files.verify() == 2


def test_request_signed_by_builder_not_signer(files, genesis, keys, release_env):
    forged = make_envelope("release", "builder1", release_env["body"], keys["builder1"], genesis)
    files.write_cert(request=forged)
    assert files.verify() == 2


def test_unsigned_request(files, release_env):
    files.write_cert(request={**release_env, "sig": "0" * 128})
    assert files.verify() == 2


def test_tampered_request_body(files, release_env):
    files.write_cert(request={**release_env, "body": {**release_env["body"], "tag": "v9.9.9"}})
    assert files.verify(tag="v9.9.9") == 2


def test_certificate_genesis_hash_differs(files):
    files.write_cert(genesis_hash="c" * 64)
    assert files.verify() == 2


def test_attestations_signed_for_other_genesis(files, keys, release_env):
    raw = genesis_raw()
    raw["network_id"] = "other-net"
    other = parse_genesis(raw)
    rid = hashlib.sha256(canonical_json(release_env["body"])).hexdigest()
    atts = [
        make_envelope("attest", s, {"request_id": rid, "result": H}, keys[s], other)
        for s in ("builder1", "builder2", "builder3")
    ]
    files.write_cert(atts=atts)
    assert files.verify() == 2  # replay from another network


@pytest.mark.parametrize(
    "raw",
    [b"", b"not json", b"[]", b'{"v":1}', b'{"v":1.0,"genesis_hash":"a"}', b"\xff\xfe" * 10],
)
def test_malformed_certificate(files, raw):
    files.write_cert(raw=raw)
    assert files.verify() == 2


def test_duplicate_keys_in_certificate(files, release_env, attest, genesis):
    atts = json.dumps([attest("builder1", H)])
    raw = (
        f'{{"v":1,"genesis_hash":"{genesis.hash}","genesis_hash":"{genesis.hash}",'
        f'"request":{json.dumps(release_env)},"attestations":{atts}}}'
    )
    files.write_cert(raw=raw.encode())
    assert files.verify() == 2


def test_oversized_certificate(files):
    files.write_cert(raw=b" " * 70000)
    assert files.verify() == 2


# exit 4: errors


def test_no_pin_is_error(files):
    assert files.verify(pin=None) == 4


def test_bad_pin_format_is_error(files):
    assert files.verify(pin="xyz") == 4


def test_genesis_differs_from_pin(files):
    assert files.verify(pin="d" * 64) == 4


def test_unreadable_file(files):
    assert files.verify(file=files.tmp / "missing") == 4


def test_unreadable_certificate(files):
    (files.tmp / "hello.matrix.json").unlink()
    assert files.verify() == 4


def test_invalid_genesis(files):
    files.gpath.write_text('{"f": 1.5}')
    assert files.verify() == 4


def test_missing_args_is_error_not_invalid(files):
    assert run(["verify", str(files.binary)]) == 4  # argparse's 2 must not read as INVALID


# keygen


def test_keygen_writes_0600_and_prints_pubkey(tmp_path, capsys):
    out = tmp_path / "k.key"
    assert run(["keygen", "--out", str(out)]) == 0
    assert capsys.readouterr().out.strip() == pubkey_hex(load_key(str(out)))
    if os.name == "posix":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_keygen_refuses_overwrite(tmp_path):
    out = tmp_path / "k.key"
    out.write_text("keep me")
    assert run(["keygen", "--out", str(out)]) == 4
    assert out.read_text() == "keep me"


def test_fuzz_mutated_certificates_never_verify_or_crash(files, capsys):
    """RFC §9.1: malformed certificates through `verify`. Every byte of a canonical certificate
    is signed or strictly checked, so no single-byte change may still give exit 0, and nothing
    may reach the generic error handler (which would mean an exception escaped a parser)."""
    import random

    original = (files.tmp / "hello.matrix.json").read_bytes()
    rng = random.Random(1234)
    for _ in range(400):
        b = bytearray(original)
        i = rng.randrange(len(b))
        b[i] = rng.choice([c for c in range(256) if c != b[i]])
        files.write_cert(raw=bytes(b))
        assert files.verify() in (1, 2, 4)
    assert "unexpected error" not in capsys.readouterr().err
    files.write_cert(raw=original)
    assert files.verify() == 0  # the unmutated certificate still verifies
