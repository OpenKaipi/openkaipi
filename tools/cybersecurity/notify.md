# Notify

Sends urgent findings to your phone or email in one message.

```
python orchestrator.py ./copy-of-your-project --authorize --notify ntfy:your-long-random-topic
```

## How to use it

1. Copy every file in `tools/cybersecurity/scripts/` into one folder.
2. You need Python 3.8 or newer. Do not install a package.
3. `--authorize` is required. Use a topic of 10 to 64 letters, digits, `-`, or `_`. Anyone who knows the topic can read it, so make it long and random.
4. For email, use `--notify email:you@example.com` and set `OPENKAIPI_SMTP_HOST`, `OPENKAIPI_SMTP_USER`, and `OPENKAIPI_SMTP_PASSWORD`. Optional: `OPENKAIPI_SMTP_PORT` (587) and `OPENKAIPI_SMTP_FROM`.
5. For your own ntfy server, set `OPENKAIPI_NTFY_SERVER` to an `https://` address.
6. The message has severity, problem name, file, and line. It does not include code or secret values.
7. If sending fails, the audit still finishes and prints a warning.

To test the channel only, copy `notifier.py` and run `python notifier.py ntfy:your-long-random-topic`. When the send works, it prints: `Test message sent. Check your phone. If nothing comes, check the topic name.`

## Example output

Two urgent findings become one message like this:

> OpenKaipi Cybersecurity: 2 urgent findings
> - [HIGH] AWS Access Key ID (app.py:3)
> - [HIGH] Dangerous OS Command (os.system) (app.py:4)
