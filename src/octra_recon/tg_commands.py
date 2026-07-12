"""Telegram long-poll command bot (no open inbound port)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .claim import claim_pipeline
from .github_lexicon import run_github_lexicon
from .mask_diff import run_mask_diff
from .rng_audit import run_rng_audit
from .sources import ReconError
from .telegram import load_telegram_settings
from .unlock_scan import scan_challenge_workspace
from .wire_audit import run_wire_audit
from .workspace import write_json


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


def _reply(token: str, chat_id: str, text: str) -> None:
    _api(
        token,
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": text[:4000],
            "disable_web_page_preview": "true",
        },
    )


def _normalize_cmd(token: str) -> str:
    """'/status@MyBot' or '/STATUS' -> '/status'."""
    t = token.strip().lower()
    if not t:
        return ""
    # strip bot mention suffix Telegram adds in groups / sometimes DMs
    t = t.split("@", 1)[0]
    if not t.startswith("/"):
        t = "/" + t
    return t


def handle_command(workspace: Path, text: str) -> str:
    raw = text.strip()
    if not raw:
        return "empty. try /help"
    # support multi-command messages: "/status /claim"
    parts = raw.split()
    cmds = [
        _normalize_cmd(p)
        for p in parts
        if p.startswith("/")
        or p.lower()
        in ("status", "scan", "claim", "help", "start", "lexicon", "lex", "wire", "mask", "rng", "stack")
    ]
    if not cmds:
        cmds = [_normalize_cmd(parts[0])]

    replies: list[str] = []
    for cmd in cmds:
        if cmd in ("/status",):
            claim = claim_pipeline(workspace)
            replies.append(
                "STATUS\n"
                f"claim_ready={claim.get('claim_ready')}\n"
                f"critical={len(claim.get('critical') or [])}\n"
                f"s_hits={len(claim.get('s_hits') or [])}\n"
                f"holdout={claim.get('holdout_file')}\n"
                f"next={'; '.join(claim.get('next_actions') or [])[:300]}"
            )
        elif cmd in ("/scan",):
            u = scan_challenge_workspace(workspace)
            replies.append(
                "SCAN\n"
                f"unlock_signal={u.get('unlock_signal')}\n"
                f"new_files={u.get('new_file_count')}"
            )
        elif cmd in ("/claim",):
            c = claim_pipeline(workspace)
            actions = c.get("next_actions") or ["nothing ready"]
            replies.append("CLAIM\n" + "\n".join(actions))
        elif cmd in ("/lexicon", "/lex"):
            # quick standard pass so TG stays responsive (~few minutes max cap)
            lex = run_github_lexicon(
                workspace,
                base=workspace.parent,
                max_candidates=1500,
                deep=False,
                skip_tested=True,
            )
            replies.append(
                "LEXICON\n"
                f"mode={lex.get('mode')}\n"
                f"tested={lex.get('tested')} skipped={lex.get('skipped_already_tested')}\n"
                f"hits={lex.get('hits')} cache={lex.get('cache_size')}\n"
                f"bip39_tokens={lex.get('bip39_unique_in_corpus')} files={lex.get('files_read')}\n"
                f"top={', '.join((lex.get('top_bip39') or [])[:12])}"
            )
        elif cmd in ("/wire",):
            w = run_wire_audit(workspace)
            sm = w.get("summary") or {}
            pl = sm.get("plaintext_interval") or {}
            replies.append(
                "WIRE\n"
                f"parse_ok={sm.get('parse_ok')} cts={sm.get('cipher_count')}\n"
                f"plaintext={pl.get('plaintext_bytes_min')}-{pl.get('plaintext_bytes_max')}\n"
                f"alert={sm.get('alert')}\n"
                f"findings={', '.join(f.get('id','') for f in (sm.get('findings') or []))}"
            )
        elif cmd in ("/mask",):
            m = run_mask_diff(workspace)
            replies.append(
                "MASK\n"
                f"status={m.get('status')}\n"
                f"domains={(m.get('lpn_domains') or {}).get('domains_seen')}\n"
                f"missing={(m.get('lpn_domains') or {}).get('missing_for_full_R')}\n"
                f"unlock={(m.get('unlock') or {}).get('unlock_signal')}"
            )
        elif cmd in ("/rng",):
            r = run_rng_audit(workspace)
            replies.append(
                "RNG\n"
                f"ok={r.get('ok')} sources={r.get('wallet_gen_sources_found')}\n"
                f"issues={'; '.join(r.get('critical_or_high') or [])[:300] or 'none'}"
            )
        elif cmd in ("/stack",):
            # light structural only (no lexicon/race) so bot stays responsive
            from .full_stack import run_full_stack

            s = run_full_stack(
                workspace,
                include_lexicon=False,
                include_race=False,
                lexicon_max=0,
            )
            replies.append(
                "STACK\n"
                f"claim_ready={s.get('claim_ready')} unlock={s.get('unlock_signal')}\n"
                f"wire={s.get('wire_parse_ok')} rng={s.get('rng_ok')} s_hits={s.get('s_hits')}\n"
                f"alerts={len(s.get('alerts') or [])}"
            )
        elif cmd in ("/help", "/start"):
            replies.append(
                "Octra race bot\n"
                "/status — claim pipeline\n"
                "/scan — unlock scan\n"
                "/claim — next actions\n"
                "/wire — secret.ct structure\n"
                "/mask — dual-mask matrix\n"
                "/rng — wallet-gen RNG audit\n"
                "/stack — full structural stack\n"
                "/lexicon — GitHub-dict key hunt (quick)\n"
                "/help — this text\n"
                "Send commands as a direct message to this bot."
            )
        else:
            replies.append(f"unknown: {cmd}. try /help")
    return "\n\n".join(replies)


def poll_once(workspace: Path, state_path: Path | None = None) -> dict[str, Any]:
    """Long-poll getUpdates once; process new messages from configured chat."""
    settings = load_telegram_settings()
    if settings is None:
        raise ReconError("Telegram not configured")
    state_path = state_path or (workspace / "logs" / "tg_offset.json")
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

    results = []
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
        # only respond to configured chat
        if chat_id != allowed_chat:
            results.append({"cmd": msg.get("text"), "ok": False, "reason": f"chat_mismatch got={chat_id} want={allowed_chat}"})
            continue
        text = msg.get("text") or ""
        # accept /commands (with optional @bot)
        if not re.match(r"^/", text.strip()) and not text.strip().lower().split()[0:1] == ["status"]:
            if not text.strip().startswith("/"):
                continue
        try:
            reply = handle_command(workspace, text)
        except Exception as error:  # noqa: BLE001
            reply = f"error: {type(error).__name__}: {error}"
        try:
            _reply(settings.bot_token, chat_id, reply)
            results.append({"cmd": text, "ok": True, "reply_preview": reply[:80]})
        except (HTTPError, URLError, TimeoutError) as error:
            results.append({"cmd": text, "ok": False, "reason": type(error).__name__})

    write_json(state_path, {"offset": max_id, "allowed_chat": allowed_chat, "last_seen_chats": seen_chats[-10:]})
    handled_ok = sum(1 for r in results if r.get("ok"))
    return {
        "ok": True,
        "handled": handled_ok,
        "updates_seen": len(updates),
        "results": results,
        "allowed_chat": allowed_chat,
    }


def poll_loop(workspace: Path, cycles: int = 0) -> dict[str, Any]:
    """
    Continuous long-poll. cycles=0 means forever (service mode).
    """
    n = 0
    last: dict[str, Any] = {}
    while True:
        last = poll_once(workspace)
        n += 1
        if cycles and n >= cycles:
            break
    return {"cycles": n, "last": last}
