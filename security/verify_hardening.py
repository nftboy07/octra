"""Negative-result checks backing security/REPORT.md. Run: PYTHONPATH=src python3 security/verify_hardening.py"""
import os
import sys
import tempfile
from pathlib import Path

from octra_recon import wallet
from octra_recon.artifacts import verify_checksums
from octra_recon.sources import ReconError
from octra_recon.workspace import safe_relative_path

failures = 0


def check(name, ok):
    global failures
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name}")


def rejects(fn):
    try:
        fn()
    except ReconError:
        return True
    return False


pk = wallet.ed25519_public_key(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
check("ed25519 matches RFC 8032 test vector 1", pk.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
seed = wallet.seed_from_mnemonic("abandon " * 11 + "about", "TREZOR")
check("BIP39 seed matches official test vector", seed.hex().startswith("c55257c360c07c72029aebc1b53c05ed"))
check("bad BIP39 checksum rejected", rejects(lambda: wallet.validate_mnemonic("abandon " * 12)))

for bad in ("../etc/passwd", "/etc/passwd", "a/../../b"):
    check(f"safe_relative_path rejects {bad!r}", rejects(lambda: safe_relative_path(bad)))

with tempfile.TemporaryDirectory() as tmp:
    ws = Path(tmp)
    (ws / "artifacts").mkdir()
    secret = ws / "outside_secret"
    secret.write_text("secret")
    os.symlink(secret, ws / "artifacts" / "pk.bin")
    (ws / "artifacts" / "SHA256SUMS").write_text("0" * 64 + "  pk.bin\n")
    check("verify_checksums refuses symlinked artifact", rejects(lambda: verify_checksums(ws)))
    (ws / "artifacts" / "SHA256SUMS").write_text("0" * 64 + "  ../outside_secret\n")
    check("verify_checksums refuses traversal in manifest", rejects(lambda: verify_checksums(ws)))

print(f"{failures} failures")
sys.exit(1 if failures else 0)
