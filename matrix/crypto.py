def keygen() -> tuple[str, str]:
    raise NotImplementedError


def load_key(path: str):
    raise NotImplementedError


def pubkey_hex(sk) -> str:
    raise NotImplementedError


def signed_bytes(genesis_hash: str, unsigned: dict) -> bytes:
    raise NotImplementedError


def sign(sk, genesis_hash: str, unsigned: dict) -> str:
    raise NotImplementedError


def verify(pubkey_hex: str, genesis_hash: str, unsigned: dict, sig_hex: str) -> bool:
    raise NotImplementedError
