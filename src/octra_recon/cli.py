"""Command-line entry point for the non-executing reconnaissance toolkit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .artifacts import detect_repeated_blocks, extract_params, verify_checksums
from .sources import ReconError, source_status, sync_sources
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
    return parser


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(args: argparse.Namespace) -> dict[str, Any]:
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
    raise ReconError("Unsupported command.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _emit(run(args))
    except ReconError as error:
        parser.exit(2, f"error: {error}\n")
    return 0
