#!/usr/bin/env python3
"""
OK Audit - Scheduler

Runs the full audit automatically, so you do not need to start it each time:

  --every 1d      run again on a fixed schedule (30m, 6h, 1d, ...)
  --watch         run again when your code folder changes
  both            run on change, and at least once per schedule

You only get alerts for NEW urgent findings. An old problem stays quiet.
If it is fixed and then comes back, you get an alert again.

Safety and cost
---------------
* Each run works on a copy of your code. The original does not change.
* There are at least --min-interval seconds between runs (default 15 minutes).
* A live chatbot (--chatbot-url) is tested at most once per --live-every
  (default 1 day), because many requests to a live system can cause problems.
* Each run counts toward your monthly budget. When the budget is used up,
  the scheduler tells you (if --notify is set) and stops.

Use it only on your own code and chatbots.

Usage
-----
    python scheduler.py ./my-project --authorize --watch --every 1d \\
        --notify ntfy:my-long-random-topic --brain

Stop it with Ctrl+C. Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import brain as brain_mod          # noqa: E402
import chatbot_auditor              # noqa: E402
import notifier as notifier_mod     # noqa: E402
import orchestrator                 # noqa: E402
from secret_scanner import SKIP_DIRS  # noqa: E402

UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_interval(text: str) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", text.strip().lower())
    if not m:
        raise ValueError(f"'{text}' is not an interval. Use for example 30m, 6h or 1d.")
    return int(m.group(1)) * UNITS[m.group(2)]


def tree_signature(root: str) -> str:
    """Cheap fingerprint of a folder: changes when any file is added/removed/edited."""
    h = hashlib.sha1()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            h.update(f"{os.path.relpath(full, root)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def load_state(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[OK Audit] Could not save scheduler state: {exc}", file=sys.stderr)


def log(msg: str) -> None:
    print(f"[OK Audit] {time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OK Audit - run audits automatically.")
    ap.add_argument("source", help="Folder with your code (a .zip works with --every only).")
    ap.add_argument("--authorize", action="store_true",
                    help="Confirm you own or may test this target. Required.")
    ap.add_argument("--every", help="Schedule, e.g. 30m, 6h, 1d.")
    ap.add_argument("--watch", action="store_true", help="Re-audit when the code changes.")
    ap.add_argument("--out", default="./reports")
    ap.add_argument("--budget", type=float, default=100.0, help="Monthly cap in USD.")
    ap.add_argument("--est-cost", type=float, default=0.0)
    ap.add_argument("--notify", help="ntfy:<topic> or email:<address>.")
    ap.add_argument("--brain", action="store_true", help="Use Claude to review findings.")
    ap.add_argument("--brain-model", default=brain_mod.DEFAULT_MODEL)
    ap.add_argument("--brain-run-cap", type=float, default=2.0)
    ap.add_argument("--chatbot-url", help="Also probe a chatbot you own (rate-limited).")
    ap.add_argument("--request-field", default="message")
    ap.add_argument("--reply-field", default="reply")
    ap.add_argument("--live-every", default="1d", help="Min time between live probes.")
    ap.add_argument("--min-interval", type=int, default=900,
                    help="Min seconds between audits (default 900).")
    ap.add_argument("--tick", type=float, default=30.0, help=argparse.SUPPRESS)
    ap.add_argument("--max-runs", type=int, default=0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if not args.authorize:
        print("Not running: --authorize is missing.\nOK Audit only tests code you own, "
              "or a test setup you have permission to test. Run again with --authorize.", file=sys.stderr)
        return 2
    if not (args.every or args.watch):
        ap.error("choose --every <interval> and/or --watch")
    if args.watch and not os.path.isdir(args.source):
        ap.error("--watch needs a folder, not a .zip")
    if not (os.path.isdir(args.source) or os.path.isfile(args.source)):
        print(f"Error: '{args.source}' does not exist.", file=sys.stderr)
        return 2
    try:
        every = parse_interval(args.every) if args.every else 0
        live_every = parse_interval(args.live_every)
        if args.notify:
            notifier_mod.parse_spec(args.notify)  # fail early on a bad setting
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if every and every < args.min_interval:
        print(f"Error: --every must be at least {args.min_interval} seconds "
              f"(--min-interval).", file=sys.stderr)
        return 2

    os.makedirs(args.out, exist_ok=True)
    state_path = os.path.join(args.out, "scheduler_state.json")
    state = load_state(state_path)
    seen = set(state.get("seen", []))
    last_live = float(state.get("last_live", 0.0))
    last_run = 0.0
    last_sig: str | None = None
    runs = 0

    log(f"Scheduler started. every={args.every or '-'} watch={args.watch} "
        f"notify={'on' if args.notify else 'off'} brain={'on' if args.brain else 'off'}. "
        "Press Ctrl+C to stop.")

    try:
        while True:
            now = time.time()
            reason = ""
            sig = tree_signature(args.source) if args.watch else None
            if last_run == 0.0:
                reason = "first run"
            elif every and now - last_run >= every:
                reason = "schedule"
            elif args.watch and sig != last_sig and now - last_run >= args.min_interval:
                reason = "code changed"

            if reason:
                ask, label = None, "live-bot"
                if args.chatbot_url and now - last_live >= live_every:
                    ask = chatbot_auditor.http_bot(
                        args.chatbot_url, args.request_field, args.reply_field)
                    label = args.chatbot_url
                log(f"Starting audit ({reason}).")
                last_sig, last_run = sig, now
                brain = brain_mod.Brain(model=args.brain_model,
                                        max_run_cost=args.brain_run_cap) if args.brain else None
                notifier = notifier_mod.parse_spec(args.notify) if args.notify else None
                try:
                    result = orchestrator.run_audit(
                        args.source, out_dir=args.out, budget=args.budget,
                        est_cost=args.est_cost, chatbot_ask=ask, chatbot_label=label,
                        brain=brain, notifier=notifier, seen=seen)
                except RuntimeError as exc:  # monthly budget reached
                    log(str(exc))
                    if notifier is not None:
                        notifier.send_text("OK Audit stopped", str(exc), urgent=True)
                    return 3
                except Exception as exc:  # noqa: BLE001 - a 24/7 loop must survive one bad run
                    log(f"Audit failed: {type(exc).__name__}: {exc}. It will try again later.")
                else:
                    seen = set(result["fingerprints"])  # fixed issues drop out, so a return re-alerts
                    if ask is not None:
                        last_live = now
                    state = {"seen": sorted(seen), "last_live": last_live}
                    save_state(state_path, state)
                    runs += 1
                    log(f"Audit done: {result['summary']}. Waiting for the next check.")
                    if args.max_runs and runs >= args.max_runs:
                        return 0
            time.sleep(args.tick)
    except KeyboardInterrupt:
        log("Stopped by user.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
