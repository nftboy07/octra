"""Command-line entry point for the non-executing reconnaissance toolkit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .artifacts import detect_repeated_blocks, extract_params, verify_checksums
from .hypotheses import run_hypotheses
from .lpn import inventory_lpn_samples, summarize_lpn, verify_lpn_checksums
from .lpn_audit import deep_audit
from .ops import (
    create_archive,
    full_ops_cycle,
    github_poll,
    heartbeat,
    integrity_check,
    process_candidates,
)
from .claim import claim_pipeline, claim_telegram_blurb
from .dashboard import build_dashboard
from .race.residual import score_candidate_s
from .race.suite import run_race_suite
from .social_watch import social_telegram_messages, social_watch
from .sources import ReconError, source_status, sync_sources
from .surface import open_surface_status
from .telegram import notify_telegram, telegram_status
from .tg_commands import poll_once
from .unlock_scan import scan_challenge_workspace, telegram_blurb
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
    lpn_inv = lpn_subparsers.add_parser("inventory", help="Parse LPN sample metadata")
    _workspace_argument(lpn_inv)
    lpn_inv.add_argument("--scan-y-bits", action="store_true")
    lpn_sums = lpn_subparsers.add_parser("verify", help="Verify lpn_samples digests")
    _workspace_argument(lpn_sums)
    lpn_sum = lpn_subparsers.add_parser("summary", help="Inventory + checksum summary")
    _workspace_argument(lpn_sum)
    lpn_audit = lpn_subparsers.add_parser(
        "audit",
        help="Deep structural audit at smoke-ui parity (rank, dups, balance, schema)",
    )
    _workspace_argument(lpn_audit)
    lpn_audit.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional limit for quick tests (omit for full 44-file audit)",
    )

    wallet = subparsers.add_parser("wallet", help="Octra BIP39 address derivation / target check")
    wallet_sub = wallet.add_subparsers(dest="wallet_command", required=True)
    wcheck = wallet_sub.add_parser("check", help="Derive address from a mnemonic and compare to target")
    wcheck.add_argument("--mnemonic", required=True)
    wcheck.add_argument("--passphrase", default="")
    wcheck.add_argument("--target", default=TARGET_ADDRESS)

    hyp = subparsers.add_parser("hypotheses", help="Cheap wallet-entropy hypothesis screen")
    hyp_sub = hyp.add_subparsers(dest="hypotheses_command", required=True)
    hyp_run = hyp_sub.add_parser("run", help="Test a few hundred public/low-entropy candidates")
    _workspace_argument(hyp_run)
    hyp_run.add_argument("--target", default=TARGET_ADDRESS)

    surface = subparsers.add_parser("surface", help="Open-surface status")
    surface_sub = surface.add_subparsers(dest="surface_command", required=True)
    surface_status = surface_sub.add_parser("status")
    surface_status.add_argument("--workspace", type=Path, default=None)

    unlock = subparsers.add_parser("unlock", help="Scan for Rku/sk/new unlock artifacts")
    unlock_sub = unlock.add_subparsers(dest="unlock_command", required=True)
    unlock_scan = unlock_sub.add_parser("scan", help="Scan challenge + artifacts trees")
    _workspace_argument(unlock_scan)

    race = subparsers.add_parser("race", help="Competitive stack to outperform smoke-ui / claim race")
    race_sub = race.add_subparsers(dest="race_command", required=True)
    race_run = race_sub.add_parser("run", help="Planted + BKW grid + body bind + composition")
    _workspace_argument(race_run)
    race_run.add_argument(
        "--full-audit",
        action="store_true",
        help="Also re-run full 44-file deep audit (slow)",
    )
    race_score = race_sub.add_parser("score-s", help="Score candidate LPN secret S on all samples")
    _workspace_argument(race_score)
    race_score.add_argument("--s-file", required=True, help="File or hex/bitstring of candidate S")
    race_score.add_argument("--holdout", default=None, help="Filename to treat as held-out test")
    race_score.add_argument("--max-rows", type=int, default=None, help="Optional per-file row cap")

    claim = subparsers.add_parser("claim", help="Claim-first pipeline (unlock + S + mnemonic)")
    claim_sub = claim.add_subparsers(dest="claim_command", required=True)
    claim_run = claim_sub.add_parser("run", help="Run full claim pipeline once")
    _workspace_argument(claim_run)

    dash = subparsers.add_parser("dashboard", help="HTML race dashboard")
    dash_sub = dash.add_subparsers(dest="dashboard_command", required=True)
    dash_build = dash_sub.add_parser("build", help="Write reports/dashboard.html")
    _workspace_argument(dash_build)

    ops = subparsers.add_parser("ops", help="24x7 integrity, heartbeat, github poll, candidates, archive")
    ops_sub = ops.add_subparsers(dest="ops_command", required=True)
    for name, help_text in (
        ("integrity", "Daily integrity + LPN checksums + unlock scan"),
        ("heartbeat", "Status heartbeat message payload"),
        ("github", "Poll GitHub commits for keyword alerts"),
        ("social", "Watch GitHub repos/issues/search + X/Twitter intel"),
        ("candidates", "Process candidates/inbox mnemonics"),
        ("archive", "Create compressed snapshot of logs/pins"),
        ("cycle", "integrity + github + social + candidates + heartbeat"),
    ):
        p = ops_sub.add_parser(name, help=help_text)
        _workspace_argument(p)

    telegram = subparsers.add_parser("telegram", help="Telegram notifications")
    telegram_subparsers = telegram.add_subparsers(dest="telegram_command", required=True)
    telegram_subparsers.add_parser("status")
    telegram_test = telegram_subparsers.add_parser("test")
    telegram_test.add_argument("--message", default="Octra Recon Telegram integration is configured.")
    telegram_poll = telegram_subparsers.add_parser("poll", help="Long-poll bot commands once")
    _workspace_argument(telegram_poll)
    return parser


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.command == "telegram" and args.telegram_command == "status":
        return telegram_status()
    if args.command == "telegram" and args.telegram_command == "test":
        return {"channel": "telegram", "status": "test_requested"}
    if args.command == "telegram" and args.telegram_command == "poll":
        return poll_once(require_workspace(args.workspace))
    if args.command == "surface" and args.surface_command == "status":
        ws = args.workspace
        if ws is not None:
            ws = require_workspace(ws)
        return open_surface_status(ws)
    if args.command == "wallet" and args.wallet_command == "check":
        return check_mnemonic_against_target(args.mnemonic, target=args.target, passphrase=args.passphrase)

    workspace = args.workspace
    if args.command == "init":
        result = init_workspace(workspace)
        # ensure ops directories
        ws = Path(result["workspace"])
        for sub in (
            "candidates/inbox",
            "candidates/processed",
            "candidates/hits",
            "candidates/s_inbox",
            "reports",
        ):
            (ws / sub).mkdir(parents=True, exist_ok=True)
        return result

    workspace = require_workspace(workspace)
    base = workspace.parent

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
    if args.command == "lpn" and args.lpn_command == "audit":
        return deep_audit(workspace, max_files=args.max_files)
    if args.command == "hypotheses" and args.hypotheses_command == "run":
        return run_hypotheses(workspace, target=args.target)
    if args.command == "unlock" and args.unlock_command == "scan":
        return scan_challenge_workspace(workspace)
    if args.command == "race" and args.race_command == "run":
        return run_race_suite(workspace, skip_full_audit=not args.full_audit)
    if args.command == "race" and args.race_command == "score-s":
        return score_candidate_s(
            workspace,
            args.s_file,
            holdout=args.holdout,
            max_rows_per_file=args.max_rows,
        )
    if args.command == "claim" and args.claim_command == "run":
        return claim_pipeline(workspace)
    if args.command == "dashboard" and args.dashboard_command == "build":
        return build_dashboard(workspace)
    if args.command == "ops":
        if args.ops_command == "integrity":
            return integrity_check(workspace)
        if args.ops_command == "heartbeat":
            return heartbeat(workspace, base=base)
        if args.ops_command == "github":
            return github_poll(workspace)
        if args.ops_command == "social":
            return social_watch(workspace)
        if args.ops_command == "candidates":
            return process_candidates(workspace)
        if args.ops_command == "archive":
            return create_archive(workspace, base=base)
        if args.ops_command == "cycle":
            return full_ops_cycle(workspace, base=base)
    raise ReconError("Unsupported command.")


def _notification_message(args: argparse.Namespace, result: dict[str, Any]) -> str | None:
    if args.command == "telegram":
        return args.message if args.telegram_command == "test" else None

    if args.command == "unlock":
        return telegram_blurb(result)

    if args.command == "ops":
        if args.ops_command == "heartbeat":
            return result.get("message")
        if args.ops_command == "integrity":
            if result.get("telegram"):
                return f"INTEGRITY+UNLOCK {result['telegram']}"
            ok = result.get("ok")
            return f"INTEGRITY ok={ok} lpn={result.get('lpn_checksums_ok')} secret_match={result.get('secret_ct_matches_manifest')}"
        if args.ops_command == "github":
            high = result.get("high_priority") or []
            if high:
                first = high[0]
                return (
                    f"GITHUB HIGH {first.get('repo')} {first.get('sha')}: {first.get('message')} "
                    f"kw={first.get('keywords')}"
                )
            n = result.get("alert_count", 0)
            if n:
                return f"GITHUB {n} new commit(s) across watched repos"
            return None  # quiet if nothing new
        if args.ops_command == "social":
            msgs = social_telegram_messages(result, max_messages=1)
            if result.get("critical_count"):
                return f"SOCIAL CRITICAL x{result['critical_count']}: " + (msgs[0] if msgs else "see logs")
            if result.get("high_count"):
                return f"SOCIAL HIGH x{result['high_count']}: " + (msgs[0] if msgs else "see logs")
            if msgs:
                return msgs[0]
            # first baseline run: short status once-ish via mode
            mode = result.get("x_mode")
            if mode and result.get("alert_count") == 0:
                return None
            return None
        if args.ops_command == "candidates":
            if result.get("hits"):
                return f"CANDIDATE HIT count={result['hits']} — verify and claim path NOW"
            if result.get("processed"):
                return f"CANDIDATES processed={result['processed']} hits=0"
            return None
        if args.ops_command == "archive":
            return f"ARCHIVE created {result.get('archive')} size={result.get('size_bytes')}"
        if args.ops_command == "cycle":
            social_msgs = result.get("social_messages") or []
            if result.get("social_critical") or result.get("candidate_hits") or result.get("unlock_signal"):
                extra = social_msgs[0] if social_msgs else ""
                return (
                    f"OPS CYCLE ALERT unlock={result.get('unlock_signal')} "
                    f"social_crit={result.get('social_critical')} social_high={result.get('social_high')} "
                    f"cand_hits={result.get('candidate_hits')} {extra}"
                )[:900]
            if result.get("social_high") or result.get("github_high"):
                extra = social_msgs[0] if social_msgs else ""
                return (
                    f"OPS CYCLE intel social_high={result.get('social_high')} "
                    f"gh_high={result.get('github_high')} {extra}"
                )[:900]
            return (
                f"OPS CYCLE ok integrity={result.get('integrity_ok')} "
                f"social={result.get('social_alerts')} x_mode={result.get('social_x_mode')} cand_hits=0"
            )

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
        elif args.lpn_command == "audit":
            parity = result.get("smoke_ui_parity") or {}
            summary = (
                f"deep audit ok={result.get('ok')} "
                f"smoke_ui_match={parity.get('matches_smoke_ui_A_ones')} "
                f"ranks_full={parity.get('all_ranks_full')} dupA={result.get('dup_A')}"
            )
        else:
            summary = f"completed: {result.get('file_count')} files, ok={result.get('ok')}"
    elif args.command == "hypotheses":
        hits = result.get("hits", 0)
        summary = f"HIT count={hits}" if hits else f"completed: tested={result.get('tested')} hits=0"
    elif args.command == "wallet":
        summary = f"match={result.get('match')}"
    elif args.command == "surface":
        summary = "open surface status emitted"
    elif args.command == "race":
        if args.race_command == "run":
            sc = result.get("scorecard_vs_smoke_ui") or {}
            summary = (
                f"suite done planted={sc.get('planted_controls')} "
                f"body_bind={sc.get('equation_body_commitment')} "
                f"S_recovery={sc.get('commodity_S_recovery')}"
            )
        else:
            summary = f"S verdict={result.get('verdict')} mean_residual={result.get('mean_residual_rate')}"
            if result.get("verdict") == "LIKELY_TRUE_SHARED_S":
                summary = "CRITICAL " + summary
    elif args.command == "claim":
        blurb = claim_telegram_blurb(result)
        if blurb:
            return blurb
        summary = f"claim_ready={result.get('claim_ready')} critical={len(result.get('critical') or [])}"
    elif args.command == "dashboard":
        summary = f"built {result.get('dashboard')}"
    return f"Octra Recon {args.command} {summary}."


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run(args)
        message = _notification_message(args, result)
        notifications: list[dict[str, str]] = []
        if message:
            notification = notify_telegram(message, required=args.command == "telegram")
            if notification is not None:
                notifications.append(notification)
        # social watch may produce multiple intel lines
        if args.command == "ops" and getattr(args, "ops_command", None) == "social":
            for extra in social_telegram_messages(result, max_messages=5):
                if message and extra == message:
                    continue
                note = notify_telegram(extra, required=False)
                if note is not None:
                    notifications.append(note)
        if args.command == "ops" and getattr(args, "ops_command", None) == "cycle":
            for extra in (result.get("social_messages") or [])[:4]:
                if message and extra in (message or ""):
                    continue
                note = notify_telegram(extra, required=False)
                if note is not None:
                    notifications.append(note)
        if notifications:
            result["notification"] = notifications[0] if len(notifications) == 1 else notifications
        _emit(result)
    except ReconError as error:
        parser.exit(2, f"error: {error}\n")
    return 0
