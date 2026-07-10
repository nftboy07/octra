"""Optional Telegram Bot API notifications without third-party dependencies."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .sources import ReconError


TELEGRAM_CONFIG_NAME = "telegram.env"
TELEGRAM_KEYS = (
    "OCTRA_TELEGRAM_BOT_TOKEN",
    "OCTRA_TELEGRAM_CHAT_ID",
    "OCTRA_TELEGRAM_TIMEOUT_SECONDS",
)


@dataclass(frozen=True)
class TelegramSettings:
    bot_token: str = field(repr=False)
    chat_id: str
    timeout_seconds: float = 10.0


class TelegramNotificationError(ReconError):
    """Raised when a configured Telegram delivery cannot complete."""


def _config_path(environ: Mapping[str, str]) -> Path:
    configured = environ.get("OCTRA_TELEGRAM_CONFIG")
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".config" / "octra-recon" / TELEGRAM_CONFIG_NAME


def _read_config_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ReconError(f"Telegram configuration permissions are too broad: {path}")

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key not in TELEGRAM_KEYS or not value:
            raise ReconError(f"Invalid Telegram configuration line {line_number} in {path}")
        if any(character.isspace() for character in value):
            raise ReconError(f"Telegram configuration value contains whitespace on line {line_number}")
        values[key] = value
    return values


def load_telegram_settings(environ: Mapping[str, str] | None = None) -> TelegramSettings | None:
    environment = os.environ if environ is None else environ
    values = _read_config_file(_config_path(environment))
    for key in TELEGRAM_KEYS:
        if environment.get(key):
            values[key] = environment[key]

    token = values.get("OCTRA_TELEGRAM_BOT_TOKEN")
    chat_id = values.get("OCTRA_TELEGRAM_CHAT_ID")
    if not token and not chat_id:
        return None
    if not token or not chat_id:
        raise ReconError("Telegram requires both OCTRA_TELEGRAM_BOT_TOKEN and OCTRA_TELEGRAM_CHAT_ID.")
    if any(character.isspace() for character in token) or any(character.isspace() for character in chat_id):
        raise ReconError("Telegram settings cannot contain whitespace.")

    timeout_text = values.get("OCTRA_TELEGRAM_TIMEOUT_SECONDS", "10")
    try:
        timeout_seconds = float(timeout_text)
    except ValueError as error:
        raise ReconError("OCTRA_TELEGRAM_TIMEOUT_SECONDS must be numeric.") from error
    if timeout_seconds <= 0 or timeout_seconds > 60:
        raise ReconError("OCTRA_TELEGRAM_TIMEOUT_SECONDS must be between 0 and 60.")
    return TelegramSettings(token, chat_id, timeout_seconds)


def telegram_status() -> dict[str, object]:
    try:
        settings = load_telegram_settings()
    except ReconError as error:
        return {"channel": "telegram", "configured": False, "error": str(error)}
    return {"channel": "telegram", "configured": settings is not None}


def send_telegram_message(settings: TelegramSettings, message: str) -> dict[str, str]:
    payload = urlencode(
        {
            "chat_id": settings.chat_id,
            "disable_web_page_preview": "true",
            "text": message,
        }
    ).encode("utf-8")
    request = Request(
        f"https://api.telegram.org/bot{settings.bot_token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "octra-recon/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=settings.timeout_seconds) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise TelegramNotificationError(f"Telegram notification failed with HTTP {error.code}.") from error
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        raise TelegramNotificationError("Telegram notification could not be delivered.") from error
    if not isinstance(response_payload, dict) or response_payload.get("ok") is not True:
        raise TelegramNotificationError("Telegram rejected the notification.")
    return {"channel": "telegram", "status": "sent"}


def notify_telegram(message: str, required: bool = False) -> dict[str, str] | None:
    try:
        settings = load_telegram_settings()
        if settings is None:
            if required:
                raise ReconError("Telegram is not configured.")
            return None
        return send_telegram_message(settings, message)
    except (TelegramNotificationError, ReconError) as error:
        if required:
            raise
        return {"channel": "telegram", "status": "failed", "error": str(error)}
