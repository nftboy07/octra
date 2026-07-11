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
from .sources import ReconError
from .telegram import load_telegram_settings
from .unlock_scan import scan_challenge_workspace
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
    cmds = [_normalize_cmd(p) for p in parts if p.startswith("/") or p.lower() in ("status", "scan", "claim", "help", "start")]
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
        elif cmd in ("/help", "/start"):
            replies.append(
                "Octra race bot\n"
                "/status — claim pipeline\n"
                "/scan — unlock scan\n"
                "/claim — next actions\n"
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
