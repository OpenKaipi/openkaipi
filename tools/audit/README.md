# OK Audit

OK Audit [TODO: final name] is a set of Python scripts that check a copy of your code for security problems.

## Tools

- `secret_scanner.py` - finds secrets left in code (API keys, tokens, private keys, passwords).
- `vuln_analyzer.py` - finds common security problems (injection, unsafe code execution, weak crypto, and more).
- `chatbot_auditor.py` - checks chatbot code for design mistakes, and can send harmless test messages to a bot you own.
- `brain.py` - optional: uses Claude to review findings and suggest fixes. Needs `anthropic` and `ANTHROPIC_API_KEY`.
- `orchestrator.py` - runs the scanners at the same time on a temporary copy and puts all reports in one ZIP.
- `notifier.py` - sends urgent findings to your phone (ntfy) or email. Uses `OPENKAIPI_NTFY_SERVER` and `OPENKAIPI_SMTP_*` variables.
- `scheduler.py` - runs the audit on a schedule or when your code changes.

## Safety

- The scanners are read-only. They do not change your code.
- Run them on a copy of your project, not the original. `orchestrator.py` and `scheduler.py` make their own temporary copy.
- Use them only on code and chatbots you own or have permission to test. Some tools need `--authorize`.
- Nothing leaves your computer unless you turn on `--brain`, `--notify`, or a live chatbot test.

## Requirements

Python 3.8+. Only the standard library, except `brain.py` (needs `anthropic`).

## Quick start

```
python tools/audit/secret_scanner.py ./copy-of-your-project
```

Reports go to `./reports/`.
