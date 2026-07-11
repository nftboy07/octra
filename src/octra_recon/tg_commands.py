"""Telegram long-poll command bot (no open inbound port)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .claim import claim_pipeline
from .sources import ReconError
from .telegram import load_telegram_settings
from .unlock_scan import scan_challenge_workspace
from .workspace import require_workspace, write_json


def _api(token: str, method: str, data: dict[str, str] | None = None) -> dict[str, Any]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    if data:
        req = Request(url, data=urlencode(data).encode("utf-8"), method="POST",
                      headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "octra-recon/1"})
    else:
        req = Request(url, headers={"User-Agent": "octra-recon/1"})
    with urlopen(req, timeout=35) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _reply(token: str, chat_id: str, text: str) -> None:
    _api(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text[:4000],
        "disable_web_page_preview": "true",
    })


def handle_command(workspace: Path, text: str) -> str:
    cmd = text.strip().split()[0].lower() if text.strip() else ""
    if cmd in ("/status", "status"):
        claim = claim_pipeline(workspace)
        return (
            f"status claim_ready={claim.get('claim_ready')} "
            f"critical={len(claim.get('critical') or [])} "
            f"holdout={claim.get('holdout_file')}"
        )
    if cmd in ("/scan", "scan"):
        u = scan_challenge_workspace(workspace)
        return f"unlock_signal={u.get('unlock_signal')} new_files={u.get('new_file_count')}"
    if cmd in ("/claim", "claim"):
        c = claim_pipeline(workspace)
        if c.get("next_actions"):
            return "CLAIM\n" + "\n".join(c["next_actions"])
        return "claim: nothing ready"
    if cmd in ("/help", "help", "/start"):
        return (
            "Octra race bot commands:\n"
            "/status — claim pipeline summary\n"
            "/scan — unlock scan\n"
            "/claim — next actions if hit\n"
            "/help — this text"
        )
    return "unknown command. /help"


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
            f"?timeout=20&offset={offset}"
        )
        req = Request(url, headers={"User-Agent": "octra-recon/1"})
        with urlopen(req, timeout=35) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError) as error:
        return {"ok": False, "error": type(error).__name__}

    results = []
    updates = payload.get("result") or []
    max_id = offset
    for upd in updates:
        uid = int(upd.get("update_id") or 0)
        max_id = max(max_id, uid + 1)
        msg = upd.get("message") or {}
        chat = msg.get("chat") or {}
        chat_id = str(chat.get("id") or "")
        # only respond to configured chat
        if chat_id != str(settings.chat_id):
            continue
        text = msg.get("text") or ""
        if not text.startswith("/"):
            continue
        try:
            reply = handle_command(workspace, text)
        except Exception as error:  # noqa: BLE001 — bot must not die
            reply = f"error: {type(error).__name__}"
        try:
            _reply(settings.bot_token, chat_id, reply)
            results.append({"cmd": text, "ok": True})
        except (HTTPError, URLError, TimeoutError):
            results.append({"cmd": text, "ok": False})

    write_json(state_path, {"offset": max_id})
    return {"ok": True, "handled": len(results), "results": results}
