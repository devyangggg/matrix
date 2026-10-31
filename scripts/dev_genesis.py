"""Generate a disposable eight-builder genesis and its private development keys."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from nacl.signing import SigningKey

REPO_PATTERN = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.ASCII)
IMAGE_PATTERN = re.compile(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", re.ASCII)


def repo_url(value: str) -> str:
    if REPO_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("repo must match https://github.com/<owner>/<repo>")
    return value


def image_digest(value: str) -> str:
    if IMAGE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("image must be <name>@sha256:<64 lowercase hex digits>")
    return value


def new_key(path: Path) -> str:
    """Store a 32-byte Ed25519 seed, returning its public key in hex."""
    key = SigningKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as file:
        file.write(key.encode().hex() + "\n")
    return key.verify_key.encode().hex()


def generate(out: Path, addrs: str, profile: str, repos: list[str], image: str) -> None:
    out.mkdir(parents=True, exist_ok=True)
    keys_dir = out / "keys"
    keys_dir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(keys_dir, 0o700)

    # A rerun must not silently replace a key used by an existing genesis.
    key_paths = [keys_dir / f"builder{i}.key" for i in range(1, 9)]
    key_paths.append(keys_dir / "release.key")
    if any(path.exists() for path in key_paths):
        raise FileExistsError(f"key files already exist in {keys_dir}; choose a fresh --out")

    nodes = []
    for number, key_path in enumerate(key_paths[:8], start=1):
        addr = f"builder{number}:7700" if addrs == "compose" else f"127.0.0.1:{7699 + number}"
        nodes.append(
            {
                "id": f"builder{number}",
                "operator": f"laptop{'ABCD'[(number - 1) // 2]}",
                "addr": addr,
                "pubkey": new_key(key_path),
            }
        )

    genesis = {
        "network_id": "matrix-dev",
        "f": 2,
        "replicas": 8,
        "threshold": 3,
        "build_timeout_s": 45 if profile == "demo" else 150,
        "request_ttl_s": 3600,
        "sync_interval_s": 5 if profile == "demo" else 10,
        "allowed_repos": repos,
        "allowed_images": {"go1.23": image},
        "allowed_goos": ["linux", "darwin", "windows"],
        "allowed_goarch": ["amd64", "arm64"],
        "release_signers": [{"id": "ci-release", "pubkey": new_key(key_paths[8])}],
        "nodes": nodes,
    }
    canonical = json.dumps(
        genesis,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    (out / "genesis.json").write_bytes(canonical + b"\n")
    (out / "genesis.sha256").write_text(
        hashlib.sha256(canonical).hexdigest() + "\n", encoding="ascii"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, required=True, help="directory for genesis and private keys"
    )
    parser.add_argument("--addrs", choices=("compose", "local"), required=True)
    parser.add_argument("--profile", choices=("demo", "full"), required=True)
    parser.add_argument(
        "--repo",
        action="append",
        type=repo_url,
        required=True,
        help="allowed GitHub repository (repeatable)",
    )
    parser.add_argument(
        "--image",
        type=image_digest,
        required=True,
        help="pinned linux/amd64 single-platform Go image digest",
    )
    args = parser.parse_args()
    generate(args.out, args.addrs, args.profile, args.repo, args.image)


if __name__ == "__main__":
    main()
