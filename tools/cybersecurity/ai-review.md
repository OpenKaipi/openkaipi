# AI review

Asks an AI model to review findings, say if each one looks real, and suggest a fix in simple English.

```
python orchestrator.py ./copy-of-your-project --authorize --brain
```

## How to use it

1. Copy every file in `tools/cybersecurity/scripts/` into one folder.
2. You need Python 3.8 or newer. The audit still runs if you skip this trick.
3. This trick needs the optional `anthropic` package and an API key in the environment variable `ANTHROPIC_API_KEY`. Do not put the key in code or in chat.
4. `--authorize` is required. The model sees masked snippets, not your full files. It writes text only. It does not edit your code.
5. Open a terminal in the scripts folder and run the command above.
6. When the review runs, the audit folder contains `AI_TRIAGE.md`.

You can set a per-run limit with `--brain-run-cap` (default 2 USD). The monthly `--budget` still applies.

## Example output

Without the optional package, a test run printed:

> [OpenKaipi Cybersecurity] AI brain off: the 'anthropic' package is not installed (pip install anthropic)
> [OpenKaipi Cybersecurity] Copy is ready. The original was not changed.
> [OpenKaipi Cybersecurity] Audit done. HIGH=1 MEDIUM=1 LOW=0
> [OpenKaipi Cybersecurity] Audit ZIP: ./reports/openkaipi_cybersecurity_20261029_190352.zip

The audit still finishes. With the package and the key set, `AI_TRIAGE.md` adds a verdict, a short reason, and a fix for each reviewed finding.
