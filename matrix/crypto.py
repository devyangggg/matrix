import re

from nacl.signing import SigningKey, VerifyKey

from .canon import canonical_json

# Lives here, not in model.py, because model imports crypto (layering); model re-exports it.
SIG_PREFIX = b"matrix/v1\0"


def keygen() -> tuple[str, str]:
    sk = SigningKey.generate()
    return sk.encode().hex(), pubkey_hex(sk)


def load_key(path: str) -> SigningKey:
    with open(path, encoding="ascii") as f:
        text = f.read()
    seed = text.removesuffix("\n")
    if not re.fullmatch(r"[0-9a-f]{64}", seed, re.ASCII):
        raise ValueError("key file must hold 64 lowercase hex characters")
    return SigningKey(bytes.fromhex(seed))


def pubkey_hex(sk: SigningKey) -> str:
    return sk.verify_key.encode().hex()


def signed_bytes(genesis_hash: str, unsigned: dict) -> bytes:
    return SIG_PREFIX + genesis_hash.encode("ascii") + b"\0" + canonical_json(unsigned)


def sign(sk: SigningKey, genesis_hash: str, unsigned: dict) -> str:
    return sk.sign(signed_bytes(genesis_hash, unsigned)).signature.hex()


def verify(pubkey_hex: str, genesis_hash: str, unsigned: dict, sig_hex: str) -> bool:
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", pubkey_hex, re.ASCII):
            return False
        if not re.fullmatch(r"[0-9a-f]{128}", sig_hex, re.ASCII):
            return False
        VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            signed_bytes(genesis_hash, unsigned), bytes.fromhex(sig_hex)
        )
        return True
    except Exception:  # noqa: BLE001  never raises (invariant 1)
        return False
