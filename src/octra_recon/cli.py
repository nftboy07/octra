"""Command-line entry point for the non-executing reconnaissance toolkit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .artifacts import detect_repeated_blocks, extract_params, verify_checksums
from .hypotheses import run_hypotheses
from .lpn import inventory_lpn_samples, summarize_lpn, verify_lpn_checksums
from .sources import ReconError, source_status, sync_sources
from .surface import open_surface_status
from .telegram import notify_telegram, telegram_status
from .wallet import TARGET_ADDRESS, check_mnemonic_against_target
from .workspace import init_workspace, inventory_sources, require_workspace, write_json


def _workspace_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", type=Path, required=True, help="Initialized investigation workspace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="octra-recon",
        description="Safe, non-executing Octra source and artifact reconnaissance.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Create an investigation workspace")
    _workspace_argument(init)

    sources = subparsers.add_parser("sources", help="Synchronize or inspect declared source repositories")
    sources_subparsers = sources.add_subparsers(dest="sources_command", required=True)
    source_sync = sources_subparsers.add_parser("sync", help="Clone and checkout declared sources without executing them")
    _workspace_argument(source_sync)
    source_status_parser = sources_subparsers.add_parser("status", help="Show checked-out source revisions")
    _workspace_argument(source_status_parser)

    inventory = subparsers.add_parser("inventory", help="Hash static files in checked-out source trees")
    _workspace_argument(inventory)

    artifacts = subparsers.add_parser("artifacts", help="Run read-only checks over local artifact files")
    artifacts_subparsers = artifacts.add_subparsers(dest="artifacts_command", required=True)
    verify = artifacts_subparsers.add_parser("verify", help="Verify artifacts/SHA256SUMS")
    _workspace_argument(verify)
    params = artifacts_subparsers.add_parser("params", help="Summarize artifacts/params.json")
    _workspace_argument(params)
    nonces = artifacts_subparsers.add_parser("nonces", help="Detect repeated fixed-size artifact blocks")
    _workspace_argument(nonces)
    nonces.add_argument("--file", default="seed.ct", help="Artifact file name")
    nonces.add_argument("--block-size", type=int, default=16, help="Heuristic block width in bytes")

    lpn = subparsers.add_parser("lpn", help="Read-only LPN sample inventory and checksum verification")
    lpn_subparsers = lpn.add_subparsers(dest="lpn_command", required=True)
    lpn_inv = lpn_subparsers.add_parser(
        "inventory",
        help="Parse LPN sample metadata, row counts, seed uniqueness, hardness notes",
    )
    _workspace_argument(lpn_inv)
    lpn_inv.add_argument(
        "--scan-y-bits",
        action="store_true",
        help="Stream y-bit statistics per file (slower; full 44-file scan)",
    )
    lpn_sums = lpn_subparsers.add_parser(
        "verify",
        help="Verify lpn_samples/* digests listed in SHA256SUMS",
    )
    _workspace_argument(lpn_sums)
    lpn_sum = lpn_subparsers.add_parser(
        "summary",
        help="Compact inventory + checksum summary for the investigation log",
    )
    _workspace_argument(lpn_sum)

    wallet = subparsers.add_parser("wallet", help="Octra BIP39 address derivation / target check")
    wallet_sub = wallet.add_subparsers(dest="wallet_command", required=True)
    wcheck = wallet_sub.add_parser("check", help="Derive address from a mnemonic and compare to target")
    wcheck.add_argument("--mnemonic", required=True, help="12-24 word BIP39 mnemonic")
    wcheck.add_argument("--passphrase", default="", help="Optional BIP39 passphrase")
    wcheck.add_argument("--target", default=TARGET_ADDRESS, help="Target oct... address")

    hyp = subparsers.add_parser("hypotheses", help="Cheap wallet-entropy hypothesis screen")
    hyp_sub = hyp.add_subparsers(dest="hypotheses_command", required=True)
    hyp_run = hyp_sub.add_parser("run", help="Test a few hundred public/low-entropy candidates")
    _workspace_argument(hyp_run)
    hyp_run.add_argument("--target", default=TARGET_ADDRESS)

    surface = subparsers.add_parser("surface", help="Print machine-readable open-surface status")
    surface_sub = surface.add_subparsers(dest="surface_command", required=True)
    surface_status = surface_sub.add_parser("status", help="Blocking pillars, FURY notes, unlock events")
    surface_status.add_argument("--workspace", type=Path, default=None)

    telegram = subparsers.add_parser("telegram", help="Inspect or test optional Telegram notifications")
    telegram_subparsers = telegram.add_subparsers(dest="telegram_command", required=True)
    telegram_subparsers.add_parser("status", help="Show whether Telegram is configured")
    telegram_test = telegram_subparsers.add_parser("test", help="Send a Telegram test message")
    telegram_test.add_argument(
        "--message",
        default="Octra Recon Telegram integration is configured.",
        help="Test message to send",
    )
    return parser


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "telegram" and args.telegram_command == "status":
        return telegram_status()
    if args.command == "telegram" and args.telegram_command == "test":
        return {"channel": "telegram", "status": "test_requested"}
    if args.command == "surface" and args.surface_command == "status":
        ws = args.workspace
        if ws is not None:
            ws = require_workspace(ws)
        return open_surface_status(ws)
    if args.command == "wallet" and args.wallet_command == "check":
        return check_mnemonic_against_target(args.mnemonic, target=args.target, passphrase=args.passphrase)

    workspace = args.workspace
    if args.command == "init":
        return init_workspace(workspace)
    workspace = require_workspace(workspace)
    if args.command == "sources" and args.sources_command == "sync":
        result = sync_sources(workspace)
        write_json(workspace / "logs" / "sources.json", result)
        return result
    if args.command == "sources" and args.sources_command == "status":
        return source_status(workspace)
    if args.command == "inventory":
        result = inventory_sources(workspace)
        report_path = workspace / "logs" / "source_inventory.json"
        write_json(report_path, result)
        return {"file_count": result["file_count"], "report": str(report_path)}
    if args.command == "artifacts" and args.artifacts_command == "verify":
        return verify_checksums(workspace)
    if args.command == "artifacts" and args.artifacts_command == "params":
        return extract_params(workspace)
    if args.command == "artifacts" and args.artifacts_command == "nonces":
        return detect_repeated_blocks(workspace, args.file, args.block_size)
    if args.command == "lpn" and args.lpn_command == "inventory":
        return inventory_lpn_samples(workspace, scan_y_bits=args.scan_y_bits)
    if args.command == "lpn" and args.lpn_command == "verify":
        return verify_lpn_checksums(workspace)
    if args.command == "lpn" and args.lpn_command == "summary":
        return summarize_lpn(workspace)
    if args.command == "hypotheses" and args.hypotheses_command == "run":
        return run_hypotheses(workspace, target=args.target)
    raise ReconError("Unsupported command.")


def _notification_message(args: argparse.Namespace, result: dict[str, Any]) -> str | None:
    if args.command == "telegram":
        return args.message if args.telegram_command == "test" else None

    summary = "completed"
    if args.command == "inventory":
        summary = f"completed: {result['file_count']} files indexed"
    elif args.command == "artifacts" and args.artifacts_command == "verify":
        summary = "completed: checksums verified" if result["ok"] else "completed: checksum mismatches found"
    elif args.command == "sources" and args.sources_command == "sync":
        summary = f"completed: {len(result['sources'])} sources synchronized"
    elif args.command == "lpn":
        if args.lpn_command == "summary":
            summary = (
                f"completed: inventory_ok={result.get('inventory_ok')} "
                f"checksums_ok={result.get('checksums_ok')}"
            )
        elif args.lpn_command == "verify":
            summary = "completed: LPN checksums ok" if result.get("ok") else "completed: LPN checksum issues"
        else:
            summary = f"completed: {result.get('file_count')} files, ok={result.get('ok')}"
    elif args.command == "hypotheses":
        hits = result.get("hits", 0)
        if hits:
            summary = f"HIT count={hits} — verify offline immediately"
        else:
            summary = f"completed: tested={result.get('tested')} hits=0"
    elif args.command == "wallet":
        summary = f"match={result.get('match')}"
    elif args.command == "surface":
        summary = "open surface status emitted"
    return f"Octra Recon {args.command} {summary}."


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
        message = _notification_message(args, result)
        if message:
            # Force-required notification only for telegram test; hits still optional channel
            notification = notify_telegram(message, required=args.command == "telegram")
            if notification is not None:
                result["notification"] = notification
        _emit(result)
    except ReconError as error:
        parser.exit(2, f"error: {error}\n")
    return 0
