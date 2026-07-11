"""Octra wallet derivation and address verification (stdlib-only).

Path (matches smoke-ui / wallet-gen public description):
  entropy128 -> BIP39 mnemonic
  seed64     = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)
  private32  = HMAC-SHA512(key="Octra seed", msg=seed64)[0:32]
  pubkey     = Ed25519(private32)
  address    = "oct" + base58(SHA256(pubkey))

Pure Ed25519 implementation adapted from the public-domain SUPERCOP/ref10
style pure-Python ports commonly used in offline tooling.
"""

from __future__ import annotations

from hashlib import pbkdf2_hmac, sha256, sha512
import hmac
from importlib import resources
from pathlib import Path
from typing import Iterable

from .sources import ReconError

TARGET_ADDRESS = "octC5eR9pLGKbpzTbDgHowkFt8HW7LZYb2gzehzxHamxuAZ"
OCTRA_HMAC_KEY = b"Octra seed"
BIP39_PASSPHRASE_PREFIX = "mnemonic"


# --- Base58 ---

_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        out.append(_B58_ALPHABET[rem])
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return (_B58_ALPHABET[0:1] * pad + out[::-1]).decode("ascii")


# --- BIP39 ---

def _load_wordlist() -> list[str]:
    candidates = [
        Path(__file__).resolve().parent / "data" / "bip39_english.txt",
    ]
    try:
        ref = resources.files("octra_recon").joinpath("data/bip39_english.txt")
        with ref.open("r", encoding="utf-8") as handle:
            words = [line.strip() for line in handle if line.strip()]
            if len(words) == 2048:
                return words
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        pass
    for path in candidates:
        if path.is_file():
            words = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if len(words) == 2048:
                return words
    raise ReconError("BIP39 English wordlist missing (data/bip39_english.txt).")


def mnemonic_from_entropy(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ReconError("BIP39 entropy must be 16/20/24/28/32 bytes.")
    words = _load_wordlist()
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    digest = sha256(entropy).digest()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(ent_bits)
    bits += bin(digest[0])[2:].zfill(8)[:cs_bits]
    out: list[str] = []
    for i in range(0, len(bits), 11):
        idx = int(bits[i : i + 11], 2)
        out.append(words[idx])
    return " ".join(out)


def validate_mnemonic(mnemonic: str) -> list[str]:
    words = _load_wordlist()
    parts = mnemonic.strip().lower().split()
    if len(parts) not in (12, 15, 18, 21, 24):
        raise ReconError(f"Invalid mnemonic length: {len(parts)}")
    word_index = {w: i for i, w in enumerate(words)}
    for part in parts:
        if part not in word_index:
            raise ReconError(f"Unknown BIP39 word: {part!r}")
    # checksum verification
    bits = "".join(bin(word_index[w])[2:].zfill(11) for w in parts)
    ent_bits = (len(parts) * 11 * 32) // 33
    cs_bits = len(parts) * 11 - ent_bits
    entropy_bits = bits[:ent_bits]
    checksum_bits = bits[ent_bits:]
    entropy = int(entropy_bits, 2).to_bytes(ent_bits // 8, "big")
    digest = sha256(entropy).digest()
    expected = bin(digest[0])[2:].zfill(8)[:cs_bits]
    if checksum_bits != expected:
        raise ReconError("BIP39 checksum invalid.")
    return parts


# --- Ed25519 (compact pure Python) ---

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = -121665 * _inv(121666) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(P: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodepoint(P: tuple[int, int]) -> bytes:
    x, y = P
    bits = bin(y)[2:].zfill(_b - 1)[::-1] + ("1" if x & 1 else "0")
    return bytes(int("".join(bits[i : i + 8][::-1]), 2) for i in range(0, _b, 8))


def _hint(m: bytes) -> int:
    h = sha512(m).digest()
    return int.from_bytes(h, "little")


def ed25519_public_key(private32: bytes) -> bytes:
    if len(private32) != 32:
        raise ReconError("Ed25519 private key must be 32 bytes.")
    h = sha512(private32).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encodepoint(_scalarmult(_B, a))


# --- Octra derivation ---

def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    parts = validate_mnemonic(mnemonic)
    normalized = " ".join(parts)
    salt = (BIP39_PASSPHRASE_PREFIX + passphrase).encode("utf-8")
    return pbkdf2_hmac("sha512", normalized.encode("utf-8"), salt, 2048, dklen=64)


def private_key_from_seed(seed64: bytes) -> bytes:
    if len(seed64) != 64:
        raise ReconError("Octra seed material must be 64 bytes.")
    return hmac.new(OCTRA_HMAC_KEY, seed64, sha512).digest()[:32]


def address_from_public_key(pubkey: bytes) -> str:
    if len(pubkey) != 32:
        raise ReconError("Ed25519 public key must be 32 bytes.")
    return "oct" + b58encode(sha256(pubkey).digest())


def address_from_mnemonic(mnemonic: str, passphrase: str = "") -> dict[str, str]:
    seed = seed_from_mnemonic(mnemonic, passphrase)
    priv = private_key_from_seed(seed)
    pub = ed25519_public_key(priv)
    addr = address_from_public_key(pub)
    return {
        "address": addr,
        "public_key_hex": pub.hex(),
        "private_key_hex": priv.hex(),  # returned for local verification only
        "matches_target": str(addr == TARGET_ADDRESS).lower(),
    }


def check_mnemonic_against_target(mnemonic: str, target: str = TARGET_ADDRESS, passphrase: str = "") -> dict[str, object]:
    result = address_from_mnemonic(mnemonic, passphrase)
    # strip private key from default check output for safer logging
    return {
        "mnemonic_words": len(mnemonic.strip().split()),
        "address": result["address"],
        "public_key_hex": result["public_key_hex"],
        "target": target,
        "match": result["address"] == target,
    }


def address_from_entropy(entropy: bytes, passphrase: str = "") -> dict[str, object]:
    mnemonic = mnemonic_from_entropy(entropy)
    check = check_mnemonic_against_target(mnemonic, passphrase=passphrase)
    check["mnemonic"] = mnemonic
    return check
