"""Telegram long-poll command bot (no open inbound port).

Design goals:
  * Always ACK immediately so the user sees a reply within seconds
  * Prefer cached reports for heavy cmds (/wire /stack /mask /rng /lexicon)
  * Continuous poll-loop friendly (one process owns getUpdates)
  * Never swallow send errors
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
import time
import traceback
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .sources import ReconError
from .telegram import load_telegram_settings
from .workspace import write_json


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _api(token: str, method: str, data: dict[str, str] | None = None, timeout: float = 35.0) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    if data:
        req = Request(
            url,
            data=urlencode(data).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "octra-recon/1",
            },
        )
    else:
        req = Request(url, headers={"User-Agent": "octra-recon/1"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _reply(token: str, chat_id: str, text: str) -> dict[str, Any]:
    """Send message; return API payload. Raises on transport failure."""
    payload = _api(
        token,
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": (text or "(empty)")[:4000],
            "disable_web_page_preview": "true",
        },
        timeout=20.0,
    )
    if not payload.get("ok"):
        raise ReconError(f"sendMessage failed: {str(payload)[:200]}")
    return payload


def _normalize_cmd(token: str) -> str:
    """'/status@MyBot' or '/STATUS' -> '/status'."""
    t = token.strip().lower()
    if not t:
        return ""
    t = t.split("@", 1)[0]
    if not t.startswith("/"):
        t = "/" + t
    return t


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _cache_age_seconds(path: Path) -> float | None:
    if not path.is_file():
        return None
    try:
        return max(0.0, time.time() - path.stat().st_mtime)
    except OSError:
        return None


def _fmt_age(seconds: float | None) -> str:
    if seconds is None:
        return "no cache"
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    return f"{seconds / 3600:.1f}h ago"


def _wants_fresh(parts: list[str]) -> bool:
    """True if user asked to recompute: /wire fresh, /wire run, /wire --fresh."""
    tokens = {p.lower().lstrip("-") for p in parts[1:]}
    return bool(tokens & {"fresh", "run", "force", "refresh", "new"})


def _wire_from_cache(workspace: Path) -> str | None:
    path = workspace / "logs" / "wire_audit.json"
    d = _load_json(path)
    if not d:
        return None
    sm = d.get("summary") or {}
    pl = sm.get("plaintext_interval") or d.get("secret_ct", {}).get("plaintext_length") or {}
    findings = sm.get("findings") or (d.get("secret_ct") or {}).get("findings") or []
    age = _fmt_age(_cache_age_seconds(path))
    return (
        f"WIRE (cached {age})\n"
        f"parse_ok={sm.get('parse_ok')} cts={sm.get('cipher_count')}\n"
        f"plaintext={pl.get('plaintext_bytes_min')}-{pl.get('plaintext_bytes_max')}\n"
        f"alert={sm.get('alert')}\n"
        f"findings={', '.join(f.get('id', '') for f in findings)}\n"
        f"tip: /wire fresh to recompute"
    )


def _stack_from_cache(workspace: Path) -> str | None:
    path = workspace / "logs" / "full_stack.json"
    d = _load_json(path)
    if not d:
        return None
    age = _fmt_age(_cache_age_seconds(path))
    alerts = d.get("alerts") or []
    return (
        f"STACK (cached {age})\n"
        f"claim_ready={d.get('claim_ready')} unlock={d.get('unlock_signal')}\n"
        f"wire={d.get('wire_parse_ok')} rng={d.get('rng_ok')} s_hits={d.get('s_hits')}\n"
        f"alerts={len(alerts)}\n"
        + (("\n".join(str(a)[:120] for a in alerts[:3]) + "\n") if alerts else "")
        + "tip: /stack fresh to recompute"
    )


def _mask_from_cache(workspace: Path) -> str | None:
    path = workspace / "logs" / "mask_diff.json"
    d = _load_json(path)
    if not d:
        return None
    age = _fmt_age(_cache_age_seconds(path))
    return (
        f"MASK (cached {age})\n"
        f"status={d.get('status')}\n"
        f"domains={(d.get('lpn_domains') or {}).get('domains_seen')}\n"
        f"missing={(d.get('lpn_domains') or {}).get('missing_for_full_R')}\n"
        f"unlock={(d.get('unlock') or {}).get('unlock_signal')}\n"
        f"tip: /mask fresh to recompute"
    )


def _rng_from_cache(workspace: Path) -> str | None:
    path = workspace / "logs" / "rng_audit.json"
    d = _load_json(path)
    if not d:
        return None
    age = _fmt_age(_cache_age_seconds(path))
    return (
        f"RNG (cached {age})\n"
        f"ok={d.get('ok')} sources={d.get('wallet_gen_sources_found')}\n"
        f"issues={'; '.join(d.get('critical_or_high') or [])[:300] or 'none'}\n"
        f"tip: /rng fresh to recompute"
    )


def handle_command(workspace: Path, text: str) -> str:
    """Synchronous command handler (may be slow for * fresh paths)."""
    raw = text.strip()
    if not raw:
        return "empty. try /help"
    parts = raw.split()
    cmds = [
        _normalize_cmd(p)
        for p in parts
        if p.startswith("/")
        or p.lower()
        in (
            "status",
            "scan",
            "claim",
            "help",
            "start",
            "lexicon",
            "lex",
            "wire",
            "mask",
            "rng",
            "stack",
            "ping",
            "days",
            "day",
            "exhaust",
        )
    ]
    if not cmds:
        cmds = [_normalize_cmd(parts[0])]

    fresh = _wants_fresh(parts)
    replies: list[str] = []

    for cmd in cmds:
        try:
            replies.append(_handle_one(workspace, cmd, fresh=fresh))
        except Exception as error:  # noqa: BLE001
            replies.append(f"error on {cmd}: {type(error).__name__}: {error}")
    return "\n\n".join(replies)


def _handle_one(workspace: Path, cmd: str, *, fresh: bool) -> str:
    # Lazy imports so bot starts even if optional modules fail
    if cmd in ("/ping",):
        return f"PONG {_now()}\nbot alive. try /help /wire /stack"

    if cmd in ("/help", "/start"):
        return (
            "Octra race bot (instant cache; add 'fresh' to recompute)\n"
            "/ping — bot alive check\n"
            "/status — claim pipeline\n"
            "/scan — unlock scan\n"
            "/claim — next actions\n"
            "/wire [fresh] — secret.ct structure\n"
            "/mask [fresh] — dual-mask matrix\n"
            "/rng [fresh] — wallet-gen RNG audit\n"
            "/stack [fresh] — full structural stack\n"
            "/days — official Day N challenge log\n"
            "/exhaust — all public intel phrases vs wallet\n"
            "/lexicon — GitHub-dict key hunt (slow)\n"
            "/help — this text"
        )

    if cmd in ("/status",):
        from .claim import claim_pipeline

        claim = claim_pipeline(workspace)
        return (
            "STATUS\n"
            f"claim_ready={claim.get('claim_ready')}\n"
            f"critical={len(claim.get('critical') or [])}\n"
            f"s_hits={len(claim.get('s_hits') or [])}\n"
            f"holdout={claim.get('holdout_file')}\n"
            f"next={'; '.join(claim.get('next_actions') or [])[:300]}"
        )

    if cmd in ("/scan",):
        from .unlock_scan import scan_challenge_workspace

        u = scan_challenge_workspace(workspace)
        return (
            "SCAN\n"
            f"unlock_signal={u.get('unlock_signal')}\n"
            f"new_files={u.get('new_file_count')}"
        )

    if cmd in ("/claim",):
        from .claim import claim_pipeline

        c = claim_pipeline(workspace)
        actions = c.get("next_actions") or ["nothing ready"]
        return "CLAIM\n" + "\n".join(actions)

    if cmd in ("/wire",):
        if not fresh:
            cached = _wire_from_cache(workspace)
            if cached:
                return cached
        from .wire_audit import run_wire_audit

        w = run_wire_audit(workspace)
        sm = w.get("summary") or {}
        pl = sm.get("plaintext_interval") or {}
        return (
            "WIRE (fresh)\n"
            f"parse_ok={sm.get('parse_ok')} cts={sm.get('cipher_count')}\n"
            f"plaintext={pl.get('plaintext_bytes_min')}-{pl.get('plaintext_bytes_max')}\n"
            f"alert={sm.get('alert')}\n"
            f"findings={', '.join(f.get('id', '') for f in (sm.get('findings') or []))}"
        )

    if cmd in ("/mask",):
        if not fresh:
            cached = _mask_from_cache(workspace)
            if cached:
                return cached
        from .mask_diff import run_mask_diff

        m = run_mask_diff(workspace)
        return (
            "MASK (fresh)\n"
            f"status={m.get('status')}\n"
            f"domains={(m.get('lpn_domains') or {}).get('domains_seen')}\n"
            f"missing={(m.get('lpn_domains') or {}).get('missing_for_full_R')}\n"
            f"unlock={(m.get('unlock') or {}).get('unlock_signal')}"
        )

    if cmd in ("/rng",):
        if not fresh:
            cached = _rng_from_cache(workspace)
            if cached:
                return cached
        from .rng_audit import run_rng_audit

        r = run_rng_audit(workspace)
        return (
            "RNG (fresh)\n"
            f"ok={r.get('ok')} sources={r.get('wallet_gen_sources_found')}\n"
            f"issues={'; '.join(r.get('critical_or_high') or [])[:300] or 'none'}"
        )

    if cmd in ("/stack",):
        if not fresh:
            cached = _stack_from_cache(workspace)
            if cached:
                return cached
        from .full_stack import run_full_stack

        s = run_full_stack(
            workspace,
            include_lexicon=False,
            include_race=False,
            lexicon_max=0,
        )
        return (
            "STACK (fresh)\n"
            f"claim_ready={s.get('claim_ready')} unlock={s.get('unlock_signal')}\n"
            f"wire={s.get('wire_parse_ok')} rng={s.get('rng_ok')} s_hits={s.get('s_hits')}\n"
            f"alerts={len(s.get('alerts') or [])}"
        )

    if cmd in ("/lexicon", "/lex"):
        from .github_lexicon import run_github_lexicon

        # Keep TG responsive: small batch
        lex = run_github_lexicon(
            workspace,
            base=workspace.parent,
            max_candidates=400,
            deep=False,
            skip_tested=True,
        )
        return (
            "LEXICON\n"
            f"mode={lex.get('mode')}\n"
            f"tested={lex.get('tested')} skipped={lex.get('skipped_already_tested')}\n"
            f"hits={lex.get('hits')} cache={lex.get('cache_size')}\n"
            f"bip39_tokens={lex.get('bip39_unique_in_corpus')} files={lex.get('files_read')}\n"
            f"top={', '.join((lex.get('top_bip39') or [])[:12])}"
        )

    if cmd in ("/days", "/day"):
        from .challenge_days import challenge_day_status, day_telegram_blurb

        return day_telegram_blurb(challenge_day_status(workspace))

    if cmd in ("/exhaust",):
        from .intel_exhaust import run_intel_exhaust

        # passphrases are slow; skip for TG responsiveness
        s = run_intel_exhaust(workspace, also_passphrases=False)
        return (
            f"EXHAUST\n"
            f"phrases={s.get('phrases_expanded')} tested={s.get('tested')}\n"
            f"hits={s.get('hits')}\n"
            f"{s.get('note')}"
        )

    return f"unknown: {cmd}. try /help"


def poll_once(workspace: Path, state_path: Path | None = None) -> dict[str, Any]:
    """Long-poll getUpdates once; process new messages from configured chat."""
    settings = load_telegram_settings()
    if settings is None:
        raise ReconError("Telegram not configured")
    state_path = state_path or (workspace / "logs" / "tg_offset.json")
    log_path = workspace / "logs" / "tg_commands.log"
    offset = 0
    if state_path.is_file():
        try:
            offset = int(json.loads(state_path.read_text(encoding="utf-8")).get("offset") or 0)
        except (json.JSONDecodeError, ValueError, TypeError):
            offset = 0

    try:
        url = (
            f"https://api.telegram.org/bot{settings.bot_token}/getUpdates"
            f"?timeout=25&offset={offset}&allowed_updates={json.dumps(['message'])}"
        )
        req = Request(url, headers={"User-Agent": "octra-recon/1"})
        with urlopen(req, timeout=40) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as error:
        return {"ok": False, "error": type(error).__name__}

    if not payload.get("ok"):
        return {"ok": False, "error": "telegram_api_not_ok", "payload": str(payload)[:200]}

    results: list[dict[str, Any]] = []
    updates = payload.get("result") or []
    max_id = offset
    allowed_chat = str(settings.chat_id).strip()
    seen_chats: list[str] = []

    for upd in updates:
        uid = int(upd.get("update_id") or 0)
        max_id = max(max_id, uid + 1)
        msg = upd.get("message") or upd.get("edited_message") or {}
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id") or "").strip()
        if chat_id:
            seen_chats.append(chat_id)
        text = (msg.get("text") or "").strip()
        if not text:
            continue

        # only respond to configured chat
        if chat_id != allowed_chat:
            results.append(
                {
                    "cmd": text,
                    "ok": False,
                    "reason": f"chat_mismatch got={chat_id} want={allowed_chat}",
                }
            )
            # still advance offset so we don't reprocess forever
            continue

        # accept /commands (with optional @bot) or bare keywords
        first = text.split()[0].lower().split("@", 1)[0]
        if not (first.startswith("/") or first in (
            "status", "scan", "claim", "help", "start", "ping",
            "wire", "mask", "rng", "stack", "lexicon", "lex", "days", "day", "exhaust",
        )):
            continue

        # 1) Immediate ACK so user always sees something
        try:
            _reply(
                settings.bot_token,
                chat_id,
                f"got {first} - working...",
            )
        except Exception as error:  # noqa: BLE001
            results.append({"cmd": text, "ok": False, "reason": f"ack_fail:{type(error).__name__}:{error}"})
            _append_log(log_path, f"ACK FAIL {text}: {error}")
            # still try final reply below

        # 2) Run command (cache-fast for wire/stack unless fresh)
        try:
            reply = handle_command(workspace, text)
        except Exception as error:  # noqa: BLE001
            reply = f"error: {type(error).__name__}: {error}\n{traceback.format_exc()[-400:]}"

        try:
            _reply(settings.bot_token, chat_id, reply)
            results.append({"cmd": text, "ok": True, "reply_preview": reply[:120]})
            _append_log(log_path, f"OK {text} -> {reply[:100]!r}")
        except Exception as error:  # noqa: BLE001
            results.append({"cmd": text, "ok": False, "reason": f"reply_fail:{type(error).__name__}:{error}"})
            _append_log(log_path, f"REPLY FAIL {text}: {error}")

    write_json(
        state_path,
        {
            "offset": max_id,
            "allowed_chat": allowed_chat,
            "last_seen_chats": seen_chats[-10:],
            "updated_at": _now(),
        },
    )
    handled_ok = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True,
        "handled": handled_ok,
        "updates_seen": len(updates),
        "results": results,
        "allowed_chat": allowed_chat,
    }


def _append_log(path: Path, line: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{_now()} {line}\n")
    except OSError:
        pass


def poll_loop(workspace: Path, cycles: int = 0) -> dict[str, Any]:
    """
    Continuous long-poll. cycles=0 means forever (service mode).
    """
    n = 0
    last: dict[str, Any] = {}
    while True:
        try:
            last = poll_once(workspace)
        except Exception as error:  # noqa: BLE001
            last = {"ok": False, "error": f"{type(error).__name__}:{error}"}
            time.sleep(3)
        n += 1
        if cycles and n >= cycles:
            break
        # tiny pause if empty short-poll error
        if not last.get("ok"):
            time.sleep(2)
    return {"cycles": n, "last": last}
