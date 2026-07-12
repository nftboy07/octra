"""Parse and audit public HFHE bounty wire artifacts (stdlib-only).

Reimplements enough of pvac_ser (pin 071b0e9) to:
  * unpack OCTRA-HFHE-BTY02 length-prefixed secret.ct
  * parse PVAC v3 cipher structure (layers, edges, seeds, nonces)
  * confirm dual-layer BASE wrap, uniqueness, plaintext-length interval

Does not decrypt. Expected outcome: structural parity with smoke-ui INFO findings.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import math
import struct
from pathlib import Path
from typing import Any

from .sources import ReconError
from .workspace import write_json

BUNDLE_MAGIC = b"OCTRA-HFHE-BTY02"
PVAC_MAGIC = b"PVAC"
PVAC_VERSION = 0x03
TAG_CIPHER = 0
RRULE_BASE = 0
RRULE_PROD = 1  # convention used in serialized rule byte for PROD in pvac

# smoke-ui published secret.ct digest (challenge artifact)
KNOWN_SECRET_SHA256 = "5da7f82724838bf7a8c4fe95fbf6d573b621c04c9b2f7ae849545cf60223fbab"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _u64(data: bytes, off: int) -> tuple[int, int]:
    if off + 8 > len(data):
        raise ReconError(f"truncated u64 at {off}")
    return struct.unpack_from("<Q", data, off)[0], off + 8


def _u32(data: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(data):
        raise ReconError(f"truncated u32 at {off}")
    return struct.unpack_from("<I", data, off)[0], off + 4


def _u16(data: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(data):
        raise ReconError(f"truncated u16 at {off}")
    return struct.unpack_from("<H", data, off)[0], off + 2


def _u8(data: bytes, off: int) -> tuple[int, int]:
    if off + 1 > len(data):
        raise ReconError(f"truncated u8 at {off}")
    return data[off], off + 1


def _fp(data: bytes, off: int) -> tuple[tuple[int, int], int]:
    lo, off = _u64(data, off)
    hi, off = _u64(data, off)
    hi &= (1 << 63) - 1
    return (lo, hi), off


def _bitvec(data: bytes, off: int) -> tuple[dict[str, Any], int]:
    nbits, off = _u64(data, off)
    nw, off = _u64(data, off)
    expected = (nbits + 63) // 64
    if nw != expected and nbits <= (1 << 20):
        # still try to skip declared words if truncated safety fails
        pass
    if off + nw * 8 > len(data):
        raise ReconError(f"truncated bitvec words nbits={nbits} nw={nw}")
    # skip word bodies
    off += nw * 8
    return {"nbits": nbits, "nw": nw}, off


def _header(data: bytes, off: int, expected_tag: int) -> tuple[int, int]:
    if off + 6 > len(data):
        raise ReconError("truncated PVAC header")
    if data[off : off + 4] != PVAC_MAGIC:
        raise ReconError(f"bad PVAC magic at {off}: {data[off:off+4]!r}")
    ver = data[off + 4]
    tag = data[off + 5]
    if ver != PVAC_VERSION:
        raise ReconError(f"unexpected PVAC version {ver}")
    if tag != expected_tag:
        raise ReconError(f"unexpected tag {tag}, want {expected_tag}")
    return ver, off + 6


def parse_layer(data: bytes, off: int) -> tuple[dict[str, Any], int]:
    rule, off = _u8(data, off)
    layer: dict[str, Any] = {"rule": rule, "rule_name": "BASE" if rule == RRULE_BASE else f"OTHER({rule})"}
    if rule == RRULE_BASE:
        ztag, off = _u64(data, off)
        nonce_lo, off = _u64(data, off)
        nonce_hi, off = _u64(data, off)
        layer["seed_ztag"] = ztag
        layer["nonce_lo"] = nonce_lo
        layer["nonce_hi"] = nonce_hi
        layer["nonce_hex"] = f"{nonce_lo:016x}{nonce_hi:016x}"
        layer["seed_key"] = f"{ztag:016x}:{layer['nonce_hex']}"
    else:
        pa, off = _u32(data, off)
        pb, off = _u32(data, off)
        layer["pa"] = pa
        layer["pb"] = pb
    n_pc, off = _u64(data, off)
    if off + n_pc * 32 > len(data):
        raise ReconError(f"truncated PC points n={n_pc}")
    pcs = [data[off + i * 32 : off + (i + 1) * 32].hex() for i in range(n_pc)]
    off += n_pc * 32
    layer["pc_count"] = n_pc
    layer["pc_sha16"] = [h[:32] for h in pcs[:8]]  # truncated for report size
    layer["pc_full"] = pcs
    return layer, off


def parse_edge(data: bytes, off: int) -> tuple[dict[str, Any], int]:
    layer_id, off = _u32(data, off)
    idx, off = _u16(data, off)
    ch, off = _u8(data, off)
    nw, off = _u64(data, off)
    weights = []
    for _ in range(nw):
        fp, off = _fp(data, off)
        weights.append(fp)
    svec, off = _bitvec(data, off)
    return {
        "layer_id": layer_id,
        "idx": idx,
        "ch": ch,
        "w_count": nw,
        "s_nbits": svec["nbits"],
    }, off


def parse_cipher(blob: bytes) -> dict[str, Any]:
    off = 0
    ver, off = _header(blob, off, TAG_CIPHER)
    slots, off = _u64(blob, off)
    nL, off = _u64(blob, off)
    layers = []
    for _ in range(nL):
        layer, off = parse_layer(blob, off)
        layers.append(layer)
    nc0, off = _u64(blob, off)
    c0 = []
    for _ in range(nc0):
        fp, off = _fp(blob, off)
        c0.append(fp)
    nE, off = _u64(blob, off)
    edges = []
    for _ in range(nE):
        e, off = parse_edge(blob, off)
        edges.append(e)
    if off != len(blob):
        raise ReconError(f"cipher trailing bytes: used={off} len={len(blob)}")
    base = sum(1 for L in layers if L["rule"] == RRULE_BASE)
    prod = sum(1 for L in layers if L["rule"] != RRULE_BASE)
    return {
        "version": ver,
        "slots": slots,
        "layer_count": nL,
        "base_layers": base,
        "prod_layers": prod,
        "c0_count": nc0,
        "edge_count": nE,
        "layers": layers,
        "edges": edges,
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def parse_bundle(data: bytes) -> dict[str, Any]:
    if not data.startswith(BUNDLE_MAGIC):
        raise ReconError(f"bad secret.ct magic: {data[:16]!r}")
    off = len(BUNDLE_MAGIC)
    count, off = _u64(data, off)
    if count == 0 or count > 1024:
        raise ReconError(f"invalid cipher count {count}")
    cts = []
    for i in range(count):
        n, off = _u64(data, off)
        if n == 0 or off + n > len(data):
            raise ReconError(f"invalid cipher length at index {i}: n={n}")
        blob = data[off : off + n]
        off += n
        try:
            ct = parse_cipher(blob)
            ct["index"] = i
            ct["blob_size"] = n
            cts.append(ct)
        except ReconError as err:
            cts.append({"index": i, "blob_size": n, "error": str(err)})
    trailing = len(data) - off
    return {
        "magic": BUNDLE_MAGIC.decode("ascii"),
        "cipher_count": count,
        "trailing_bytes": trailing,
        "parse_complete": trailing == 0 and all("error" not in c for c in cts),
        "ciphers": cts,
    }


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _plaintext_length_interval(cipher_count: int) -> dict[str, Any]:
    """enc_text: 1 length CT + ceil(L/15) payload CTs → L in [15*(n-2)+1, 15*(n-1)]."""
    if cipher_count < 2:
        return {"note": "too few ciphertexts for length model"}
    payload_blocks = cipher_count - 1
    # length CT + k blocks of 15 bytes each for payload of length L where ceil(L/15)=k
    # L in [15*(k-1)+1, 15*k] for k>=1; for k=payload_blocks
    k = payload_blocks
    lo = 15 * (k - 1) + 1 if k >= 1 else 0
    hi = 15 * k
    return {
        "model": "1 length-CT + ceil(L/15) payload CTs of 15 bytes",
        "cipher_count": cipher_count,
        "payload_block_count": k,
        "plaintext_bytes_min": lo,
        "plaintext_bytes_max": hi,
        "smoke_ui_interval": "301-315 for count=22",
        "matches_smoke_ui_22": cipher_count == 22 and lo == 301 and hi == 315,
    }


def audit_secret_ct(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    bundle = parse_bundle(data)
    seeds: list[str] = []
    nonces: list[str] = []
    pcs: list[str] = []
    total_edges = 0
    total_base = 0
    total_prod = 0
    dual_layer_cts = 0
    parse_errors = 0
    for ct in bundle["ciphers"]:
        if "error" in ct:
            parse_errors += 1
            continue
        total_edges += ct["edge_count"]
        total_base += ct["base_layers"]
        total_prod += ct["prod_layers"]
        if ct["base_layers"] == 2 and ct["prod_layers"] == 0:
            dual_layer_cts += 1
        for L in ct.get("layers") or []:
            if L.get("rule") == RRULE_BASE:
                seeds.append(L.get("seed_key", ""))
                nonces.append(L.get("nonce_hex", ""))
            for h in L.get("pc_full") or []:
                pcs.append(h)

    seed_dup = [k for k, v in Counter(seeds).items() if v > 1 and k]
    nonce_dup = [k for k, v in Counter(nonces).items() if v > 1 and k]
    pc_dup = [k for k, v in Counter(pcs).items() if v > 1 and k]

    length = _plaintext_length_interval(bundle["cipher_count"])

    findings = []
    if bundle["cipher_count"] == 22 and length.get("matches_smoke_ui_22"):
        findings.append({
            "id": "OCTRA-HFHE-INFO-001",
            "severity": "info",
            "detail": "Cipher count 22 narrows plaintext length to 301–315 bytes (same as smoke-ui).",
        })
    if dual_layer_cts == bundle["cipher_count"] and parse_errors == 0:
        findings.append({
            "id": "DUAL_BASE_WRAP",
            "severity": "info",
            "detail": f"All {dual_layer_cts} CTs have exactly 2 BASE layers / 0 PROD (wrapped dual-mask layout).",
        })
    if not seed_dup and not nonce_dup:
        findings.append({
            "id": "SEED_NONCE_UNIQUE",
            "severity": "info",
            "detail": "No repeated base-layer seed/nonce pairs across the bundle.",
        })
    else:
        findings.append({
            "id": "SEED_NONCE_COLLISION",
            "severity": "high",
            "detail": f"Duplicate seeds={len(seed_dup)} nonces={len(nonce_dup)} — investigate PRF/seed reuse.",
        })
    if pc_dup:
        findings.append({
            "id": "PC_COLLISION",
            "severity": "high",
            "detail": f"{len(pc_dup)} repeated Pedersen commitments.",
        })
    if digest.lower() == KNOWN_SECRET_SHA256:
        findings.append({
            "id": "SECRET_CT_KNOWN_DIGEST",
            "severity": "info",
            "detail": "Matches published bounty secret.ct SHA-256.",
        })

    # structural alerts that would change claim race
    alert = any(f["severity"] == "high" for f in findings)

    return {
        "file": str(path),
        "size": len(data),
        "sha256": digest,
        "shannon_bits_per_byte": round(_shannon(data), 4),
        "bundle": {
            "magic": bundle["magic"],
            "cipher_count": bundle["cipher_count"],
            "trailing_bytes": bundle["trailing_bytes"],
            "parse_complete": bundle["parse_complete"],
            "parse_errors": parse_errors,
            "total_base_layers": total_base,
            "total_prod_layers": total_prod,
            "total_edges": total_edges,
            "dual_base_cipher_count": dual_layer_cts,
            "unique_seeds": len(set(seeds)),
            "unique_nonces": len(set(nonces)),
            "unique_pcs": len(set(pcs)),
            "duplicate_seeds": len(seed_dup),
            "duplicate_nonces": len(nonce_dup),
            "duplicate_pcs": len(pc_dup),
        },
        "plaintext_length": length,
        "cipher_summaries": [
            {
                "index": c.get("index"),
                "size": c.get("blob_size") or c.get("size"),
                "layers": c.get("layer_count"),
                "base": c.get("base_layers"),
                "prod": c.get("prod_layers"),
                "edges": c.get("edge_count"),
                "slots": c.get("slots"),
                "error": c.get("error"),
            }
            for c in bundle["ciphers"]
        ],
        "findings": findings,
        "alert": alert,
        "decrypt_possible_from_wire_alone": False,
        "note": (
            "Structural wire audit only. Dual independent masks R0,R1 and m block plaintext "
            "recovery without secret material. Length interval is an INFO leak, not a key."
        ),
    }


def audit_pk_bin(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    # compressed pk often starts with raw or header — best-effort PVAC tag scan
    pvac_hits = []
    start = 0
    while True:
        i = data.find(PVAC_MAGIC, start)
        if i < 0:
            break
        tag = data[i + 5] if i + 6 <= len(data) else None
        pvac_hits.append({"offset": i, "version": data[i + 4] if i + 5 <= len(data) else None, "tag": tag})
        start = i + 4
        if len(pvac_hits) > 5:
            break
    return {
        "file": str(path),
        "size": len(data),
        "sha256": digest,
        "shannon_bits_per_byte": round(_shannon(data), 4),
        "pvac_headers_found": pvac_hits,
        "note": "Pubkey is public; does not alone decrypt secret.ct.",
    }


def run_wire_audit(workspace: Path) -> dict[str, Any]:
    artifacts = workspace / "artifacts"
    secret = artifacts / "secret.ct"
    pk = artifacts / "pk.bin"
    params = artifacts / "params.json"

    report: dict[str, Any] = {
        "checked_at": _now(),
        "artifacts_dir": str(artifacts),
    }
    if secret.is_file() and not secret.is_symlink():
        report["secret_ct"] = audit_secret_ct(secret)
    elif secret.is_file():
        # follow symlink carefully for size/hash only via read
        try:
            report["secret_ct"] = audit_secret_ct(secret.resolve())
        except (OSError, ReconError) as err:
            report["secret_ct"] = {"error": str(err)}
    else:
        # try linked challenge path
        alt = workspace / "repos" / "hfhe-challenge" / "secret.ct"
        if alt.is_file():
            report["secret_ct"] = audit_secret_ct(alt)
        else:
            report["secret_ct"] = {"error": "secret.ct missing"}

    if pk.is_file():
        try:
            report["pk_bin"] = audit_pk_bin(pk if not pk.is_symlink() else pk.resolve())
        except (OSError, ReconError) as err:
            report["pk_bin"] = {"error": str(err)}
    else:
        alt_pk = workspace / "repos" / "hfhe-challenge" / "pk.bin"
        if alt_pk.is_file():
            report["pk_bin"] = audit_pk_bin(alt_pk)
        else:
            report["pk_bin"] = {"error": "pk.bin missing"}

    if params.is_file():
        import json

        try:
            report["params"] = json.loads(params.read_text(encoding="utf-8"))
        except json.JSONDecodeError as err:
            report["params"] = {"error": str(err)}

    sc = report.get("secret_ct") or {}
    report["summary"] = {
        "parse_ok": bool((sc.get("bundle") or {}).get("parse_complete")),
        "cipher_count": (sc.get("bundle") or {}).get("cipher_count"),
        "plaintext_interval": sc.get("plaintext_length"),
        "alert": bool(sc.get("alert")),
        "findings": sc.get("findings") or [],
    }
    write_json(workspace / "logs" / "wire_audit.json", report)

    # compact human report
    md = workspace / "reports" / "WIRE_AUDIT.md"
    md.parent.mkdir(parents=True, exist_ok=True)
    b = sc.get("bundle") or {}
    pl = sc.get("plaintext_length") or {}
    lines = [
        "# Wire audit (secret.ct)",
        "",
        f"Generated: {report['checked_at']}",
        "",
        f"- parse_ok: **{report['summary']['parse_ok']}**",
        f"- cipher_count: **{b.get('cipher_count')}**",
        f"- dual_base_cts: **{b.get('dual_base_cipher_count')}**",
        f"- total_edges: **{b.get('total_edges')}**",
        f"- plaintext: **{pl.get('plaintext_bytes_min')}–{pl.get('plaintext_bytes_max')}** bytes",
        f"- sha256: `{sc.get('sha256')}`",
        "",
        "## Findings",
        "",
    ]
    for f in sc.get("findings") or []:
        lines.append(f"- **{f['id']}** ({f['severity']}): {f['detail']}")
    lines += [
        "",
        "## Decrypt?",
        "",
        "No. Dual independent masks block recovery from public wire alone.",
        "",
    ]
    md.write_text("\n".join(lines), encoding="utf-8")
    report["markdown"] = str(md)
    return report


def wire_telegram_blurb(report: dict[str, Any]) -> str | None:
    if report.get("summary", {}).get("alert"):
        findings = report["summary"].get("findings") or []
        high = [f["id"] for f in findings if f.get("severity") == "high"]
        return f"WIRE ALERT: {', '.join(high) or 'anomaly'} — inspect wire_audit.json"
    return None
