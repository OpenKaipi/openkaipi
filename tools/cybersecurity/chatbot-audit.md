# Chatbot audit

Checks chatbot code you own for design mistakes, and can send a few harmless test messages to a bot you own.

```
python chatbot_auditor.py ./copy-of-your-bot --authorize
```

## How to use it

1. Copy these three files into the same folder: `chatbot_auditor.py`, `secret_scanner.py`, and `vuln_analyzer.py`. They are in `tools/cybersecurity/scripts/`.
2. You need Python 3.8 or newer. Do not install a package.
3. `--authorize` is required. Use this only on a chatbot you own or may test.
4. For a code check, point the command at a copy of the bot code. The script only reads the files.
5. To try the built-in weak demo bot, run `python chatbot_auditor.py --demo --authorize`.
6. To test a bot you own over HTTP, add `--url`, `--request-field`, and `--reply-field`. The default fields are `message` and `reply`.
7. Open the Markdown report in `./reports/`.

## Example output

A small test bot file prints lines like these:

> [OpenKaipi Cybersecurity] Static scan of chatbot code: /home/me/copy-of-your-bot
> [OpenKaipi Cybersecurity] Done. 1 finding(s): HIGH=1 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] Report (Markdown): ./reports/chatbot_report_20261029_190241.md
> [OpenKaipi Cybersecurity] Report (JSON):     ./reports/chatbot_report_20261029_190241.json

The report table had this row:

> | 1 | HIGH | User Text Glued Into System Prompt | `app.py` | 7 |

The built-in demo bot prints `Live test of: demo-bot` and, in a test run, `6 finding(s): HIGH=2 MEDIUM=3 LOW=1`.
