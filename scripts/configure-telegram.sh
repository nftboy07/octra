#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/octra-recon"
CONFIG_FILE="${CONFIG_DIR}/telegram.env"

install -d -m 700 "${CONFIG_DIR}"

read -r -s -p "Telegram bot token: " BOT_TOKEN
printf '\n'
read -r -p "Telegram chat ID: " CHAT_ID

if [[ -z "${BOT_TOKEN}" || -z "${CHAT_ID}" ]]; then
  echo "Both the bot token and chat ID are required." >&2
  exit 1
fi

if [[ "${BOT_TOKEN}" =~ [[:space:]] || "${CHAT_ID}" =~ [[:space:]] ]]; then
  echo "The bot token and chat ID cannot contain whitespace." >&2
  exit 1
fi

umask 077
{
  printf 'OCTRA_TELEGRAM_BOT_TOKEN=%s\n' "${BOT_TOKEN}"
  printf 'OCTRA_TELEGRAM_CHAT_ID=%s\n' "${CHAT_ID}"
  printf 'OCTRA_TELEGRAM_TIMEOUT_SECONDS=10\n'
} > "${CONFIG_FILE}"
chmod 600 "${CONFIG_FILE}"

echo "Telegram configuration saved to ${CONFIG_FILE}."
