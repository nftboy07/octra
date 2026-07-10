# Telegram notifications

The toolkit can send short Telegram messages when a supported CLI command completes
or fails. It uses `https://api.telegram.org` through Python's standard library and
does not start a polling bot, web server, scheduled task, or background process.

## Configure

Create a bot through BotFather, start a direct chat with it or add it to the target
group/channel, then obtain the destination chat ID. On the VPS, run:

```bash
sudo -u octra -H bash /home/octra/octra_investigation/toolkit/scripts/configure-telegram.sh
```

The interactive script writes an owner-only configuration file at
`/home/octra/.config/octra-recon/telegram.env`. The same values can instead be
provided through `OCTRA_TELEGRAM_BOT_TOKEN` and `OCTRA_TELEGRAM_CHAT_ID`
environment variables. Environment variables take precedence over the file.

Verify the integration without disclosing configuration values:

```bash
sudo -u octra -H /home/octra/octra_investigation/toolkit/.venv/bin/octra-recon telegram status
sudo -u octra -H /home/octra/octra_investigation/toolkit/.venv/bin/octra-recon telegram test
```

`telegram status` reveals only whether both settings are available. Notification
failures do not fail the underlying reconnaissance command; they are included as a
sanitized status in its JSON output.

## Security

- Never commit the generated `telegram.env` file or paste the bot token into a
  command line, issue, or chat.
- Keep the configuration file owned by `octra` with permission mode `0600`.
- Use a dedicated bot and a destination chat limited to intended recipients.
