# Schedule

Runs the full audit again on a timer, or when your code folder changes. You only get alerts for new urgent findings.

```
python scheduler.py ./copy-of-your-project --authorize --every 1d
```

## How to use it

1. Copy every file in `tools/cybersecurity/scripts/` into one folder.
2. You need Python 3.8 or newer. Do not install a package.
3. `--authorize` is required. Use this only on code you own or may test.
4. `--every` takes a gap such as `30m`, `6h`, or `1d`. The default minimum gap is 15 minutes (`--min-interval 900`).
5. Add `--watch` to run again when the folder changes. `--watch` needs a folder, not a `.zip`.
6. Each run uses a copy of your code. Stop the scheduler with Ctrl+C.
7. Add `--notify` or `--brain` the same way as on the full audit page. A live chatbot URL is tested at most once per day unless you change `--live-every`.

## Example output

A short test used `--every 1s` so it could finish. It printed:

> [OpenKaipi Cybersecurity] 2026-10-29 19:02:44 Scheduler started. every=1s watch=False notify=off brain=off. Press Ctrl+C to stop.
> [OpenKaipi Cybersecurity] 2026-10-29 19:02:44 Starting audit (first run).
> [OpenKaipi Cybersecurity] Copy is ready. The original was not changed.
> [OpenKaipi Cybersecurity] Audit done. HIGH=3 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] 2026-10-29 19:02:44 Audit done: {'HIGH': 3, 'MEDIUM': 0, 'LOW': 0}. Waiting for the next check.
