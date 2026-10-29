#!/usr/bin/env python3
"""
OpenKaipi Cybersecurity - Orchestrator

This runs the full audit:

  1. Checks that you confirmed you can test this target (--authorize).
  2. Makes a temporary COPY of your code and works only on the copy.
  3. Runs the secret scanner, the vulnerability analyzer and the chatbot
     auditor at the same time, in parallel threads.
  4. Shows an alert right away for each urgent (HIGH) finding, while the
     rest of the audit keeps running.
  5. Follows a monthly budget (for example $100 per month) and stops when
     it is used up.
  6. Puts all reports in one audit ZIP file.

It does not change your original code and does not attack any live system.

Use it only on your own code.

Usage
-----
    # --authorize confirms you own or can test the target
    python orchestrator.py /path/to/your/project --authorize

    # from a .zip of your code
    python orchestrator.py /path/to/project.zip --authorize

    # options
    python orchestrator.py ./project --authorize \
        --out ./reports --budget 100 --est-cost 0

Uses only the Python standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import zipfile

# Make the sibling engine modules importable no matter where we are run from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secret_scanner   # noqa: E402
import vuln_analyzer     # noqa: E402
import chatbot_auditor   # noqa: E402
import brain as brain_mod  # noqa: E402
import notifier as notifier_mod  # noqa: E402


# --------------------------------------------------------------------------- #
# Budget ledger (monthly spend cap)
# --------------------------------------------------------------------------- #

class BudgetLedger:
    """Tracks spend for the current month and refuses to run once it is spent.

    A static audit costs almost nothing. This limit is mostly for the AI
    brain (brain.py), so it does not spend more than you allow. The ledger is a small JSON
    file so the limit survives across runs.
    """

    def __init__(self, path: str, monthly_limit_usd: float) -> None:
        self.path = path
        self.monthly_limit_usd = float(monthly_limit_usd)
        self.month = _dt.date.today().strftime("%Y-%m")
        self.spent = 0.0
        self.runs = 0
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("month") == self.month:
                self.spent = float(data.get("spent", 0.0))
                self.runs = int(data.get("runs", 0))
        except (OSError, ValueError):
            pass  # no ledger yet, or new month -> start fresh

    def _save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "month": self.month,
                        "spent": round(self.spent, 4),
                        "runs": self.runs,
                        "monthly_limit_usd": self.monthly_limit_usd,
                    },
                    fh,
                    indent=2,
                )
        except OSError:
            pass

    def remaining(self) -> float:
        return max(0.0, self.monthly_limit_usd - self.spent)

    def can_afford(self, est_cost: float) -> bool:
        return (self.spent + est_cost) <= self.monthly_limit_usd

    def record(self, cost: float) -> None:
        self.spent += max(0.0, float(cost))
        self.runs += 1
        self._save()


# --------------------------------------------------------------------------- #
# Isolated copy of the code
# --------------------------------------------------------------------------- #

def make_isolated_copy(source: str, workspace: str) -> str:
    """Copy a folder, or extract a .zip, into an isolated workspace.

    Returns the path to the copy. The original 'source' is never modified.
    """
    os.makedirs(workspace, exist_ok=True)
    copy_root = os.path.join(workspace, "code_copy")
    if os.path.isdir(copy_root):
        shutil.rmtree(copy_root, ignore_errors=True)

    if os.path.isdir(source):
        shutil.copytree(source, copy_root)
    elif zipfile.is_zipfile(source):
        os.makedirs(copy_root, exist_ok=True)
        with zipfile.ZipFile(source) as zf:
            for member in zf.namelist():
                # Guard against zip-slip: never let a member escape copy_root.
                dest = os.path.realpath(os.path.join(copy_root, member))
                if not dest.startswith(os.path.realpath(copy_root) + os.sep) \
                        and dest != os.path.realpath(copy_root):
                    raise ValueError(f"Unsafe path in zip: {member}")
            zf.extractall(copy_root)
    else:
        raise ValueError(f"'{source}' is not a folder or a .zip file.")

    return copy_root


# --------------------------------------------------------------------------- #
# Normalizing findings from both engines into one shape
# --------------------------------------------------------------------------- #

def _normalize(engine: str, f) -> dict:
    if engine == "secrets":
        return {
            "engine": "Secret Scanner",
            "severity": f.severity,
            "title": f.rule,
            "file": f.file,
            "line": f.line,
            "detail": f.masked_snippet,
            "advice": f.advice,
            "fingerprint": f.fingerprint,
        }
    return {
        "engine": "Chatbot Auditor" if engine == "chatbot" else "Vulnerability Analyzer",
        "severity": f.severity,
        "title": f.rule,
        "file": f.file,
        "line": f.line,
        "detail": f.code,
        "advice": f"{f.attack_story} FIX: {f.fix}",
        "fingerprint": f.fingerprint,
    }


# --------------------------------------------------------------------------- #
# Alerting
# --------------------------------------------------------------------------- #

_print_lock = threading.Lock()


def default_alert(finding: dict, alerts_log: str) -> None:
    """Instant urgent alert. Prints now and appends to an alerts log.

    """
    line = (
        f"URGENT [{finding['severity']}] {finding['title']} "
        f"-> {finding['file']}:{finding['line']}\n"
        f"   {finding['advice']}"
    )
    with _print_lock:
        print(line, flush=True)
        try:
            with open(alerts_log, "a", encoding="utf-8") as fh:
                fh.write(f"[{_dt.datetime.now().isoformat(timespec='seconds')}] {line}\n")
        except OSError:
            pass


def _brain_worker(brain, q: "queue.Queue", alerts_log: str) -> None:
    """Runs beside the scanners: explains urgent findings and drafts fixes.

    Each finding was already announced instantly by the raw alert; this adds
    the AI's plain-language reading and fix as soon as it is ready.
    """
    done = False
    while not done:
        item = q.get()
        if item is None:
            break
        batch = [item]
        time.sleep(0.3)  # let a burst of findings accumulate into one call
        while len(batch) < brain_mod.BATCH_SIZE:
            try:
                nxt = q.get_nowait()
            except queue.Empty:
                break
            if nxt is None:
                done = True
                break
            batch.append(nxt)
        by_fp = {f["fingerprint"]: f for f in batch}
        for res in brain.triage(batch):
            f = by_fp[res["fingerprint"]]
            line = (
                f"AI [{res['verdict']}] {f['title']} -> {f['file']}:{f['line']}\n"
                f"   {res['reason']}"
            )
            with _print_lock:
                print(line, flush=True)
                try:
                    with open(alerts_log, "a", encoding="utf-8") as fh:
                        fh.write(f"[{_dt.datetime.now().isoformat(timespec='seconds')}] {line}\n")
                except OSError:
                    pass
    # Keep draining so the producer never blocks if we stopped early.


# --------------------------------------------------------------------------- #
# The audit
# --------------------------------------------------------------------------- #

def run_audit(
    source: str,
    out_dir: str = "./reports",
    budget: float = 100.0,
    est_cost: float = 0.0,
    alert_cb=None,
    chatbot_ask=None,
    chatbot_label: str = "live-bot",
    brain=None,
    notifier=None,
    seen: "set[str] | None" = None,
    allowed_probes: "set[str] | None" = None,
) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    ledger = BudgetLedger(os.path.join(out_dir, "budget_ledger.json"), budget)

    if not ledger.can_afford(est_cost):
        raise RuntimeError(
            f"Monthly budget reached. Limit=${ledger.monthly_limit_usd:.2f}, "
            f"already spent=${ledger.spent:.2f}. The audit did not run."
        )

    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    audit_dir = os.path.join(out_dir, f"audit_{stamp}")
    os.makedirs(audit_dir, exist_ok=True)
    alerts_log = os.path.join(audit_dir, "urgent_alerts.log")

    if alert_cb is None:
        alert_cb = lambda f: default_alert(f, alerts_log)  # noqa: E731

    workspace = tempfile.mkdtemp(prefix="openkaipi_cybersecurity_")
    results: dict[str, list] = {}

    brain_q: "queue.Queue" = queue.Queue()
    brain_thread = None
    if brain is not None:
        if not brain.available:
            print(f"[OpenKaipi Cybersecurity] AI brain off: {brain.disabled_reason}")
            brain = None
        else:
            # The brain may never spend more than what the month has left.
            brain.max_run_cost = min(brain.max_run_cost, max(0.0, ledger.remaining() - est_cost))
            print(f"[OpenKaipi Cybersecurity] AI brain on ({brain.model}), run cap ${brain.max_run_cost:.2f}.")
            brain_thread = threading.Thread(
                target=_brain_worker, args=(brain, brain_q, alerts_log), daemon=True)
            brain_thread.start()

    try:
        copy_root = make_isolated_copy(source, workspace)
        print(f"[OpenKaipi Cybersecurity] Copy is ready. The original was not changed.")

        # --- Multitasking: run both engines at the same time. ---------------
        def worker(name: str, fn) -> None:
            findings = fn(copy_root)
            results[name] = findings
            # Fire instant alerts for urgent (HIGH) findings right away,
            # while the other engine may still be running.
            for f in findings:
                if f.severity == "HIGH":
                    norm = _normalize("chatbot" if name.startswith("chatbot") else name, f)
                    if seen is not None and norm["fingerprint"] in seen:
                        continue  # already reported in an earlier run: stay quiet
                    alert_cb(norm)
                    if notifier is not None:
                        notifier.add(norm)
                    if brain_thread is not None:
                        brain_q.put(norm)

        threads = [
            threading.Thread(target=worker, args=("secrets", secret_scanner.scan_project)),
            threading.Thread(target=worker, args=("vulns", vuln_analyzer.analyze_project)),
            threading.Thread(target=worker, args=("chatbot", chatbot_auditor.analyze_project)),
        ]
        if chatbot_ask is not None:
            # Optional live probe of a chatbot you own, in parallel with the rest.
            threads.append(threading.Thread(
                target=worker,
                args=("chatbot_live", lambda _root: chatbot_auditor.probe_chatbot(
                    chatbot_ask, chatbot_label, allowed=allowed_probes)),
            ))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if notifier is not None:
            notifier.close()  # send any grouped urgent message still waiting

        all_norm = [_normalize("secrets", f) for f in results.get("secrets", [])] + \
                   [_normalize("vulns", f) for f in results.get("vulns", [])] + \
                   [_normalize("chatbot", f) for f in
                    results.get("chatbot", []) + results.get("chatbot_live", [])]
        if brain_thread is not None:
            # HIGH ones were queued as they arrived; now add MEDIUM, then stop.
            for f in all_norm:
                if f["severity"] == "MEDIUM" and not (seen and f["fingerprint"] in seen):
                    brain_q.put(f)
            brain_q.put(None)
            brain_thread.join()
            brain.write_report(os.path.join(audit_dir, "AI_TRIAGE.md"), all_norm)

        secret_findings = results.get("secrets", [])
        vuln_findings = results.get("vulns", [])
        chatbot_findings = results.get("chatbot", []) + results.get("chatbot_live", [])

        # --- Individual engine reports (reusing each engine's own writer). --
        secret_scanner.write_reports(secret_findings, copy_root, audit_dir)
        vuln_analyzer.write_reports(vuln_findings, copy_root, audit_dir)
        # Only write a chatbot report when something chatbot-related was found.
        if chatbot_findings:
            vuln_analyzer.write_reports(
                chatbot_findings, copy_root, audit_dir,
                tool_name="Chatbot Auditor", file_prefix="chatbot_report")

        # --- Combined executive summary + manifest. -------------------------
        all_findings = [_normalize("secrets", f) for f in secret_findings] + \
                       [_normalize("vulns", f) for f in vuln_findings] + \
                       [_normalize("chatbot", f) for f in chatbot_findings]
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        summary = _executive_summary(source, stamp, counts, all_findings)
        if brain is not None:
            summary += "\n".join(brain.summary_lines()) + "\n"
        with open(os.path.join(audit_dir, "EXECUTIVE_SUMMARY.md"), "w", encoding="utf-8") as fh:
            fh.write(summary)

        manifest = {
            "tool": "OpenKaipi Cybersecurity",
            "source": os.path.abspath(source),
            "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
            "summary": counts,
            "total_findings": len(all_findings),
            "budget": {
                "monthly_limit_usd": ledger.monthly_limit_usd,
                "spent_before_usd": round(ledger.spent, 4),
                "estimated_run_cost_usd": est_cost,
                "ai_cost_usd": round(brain.spent, 4) if brain is not None else 0.0,
            },
            "ai_brain": (
                {"model": brain.model, "calls": brain.calls,
                 "reviewed": len(brain.results), "stopped_because": brain.disabled_reason}
                if brain is not None else None
            ),
        }
        with open(os.path.join(audit_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        # --- Package everything into the audit ZIP. -------------------------
        zip_path = os.path.join(out_dir, f"openkaipi_cybersecurity_{stamp}.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in sorted(os.listdir(audit_dir)):
                zf.write(os.path.join(audit_dir, name), arcname=name)

        ledger.record(est_cost + (brain.spent if brain is not None else 0.0))

        if brain is not None and brain.disabled_reason:
            print(f"[OpenKaipi Cybersecurity] AI brain stopped early: {brain.disabled_reason}")
        print(f"[OpenKaipi Cybersecurity] Audit done. "
              f"HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
        print(f"[OpenKaipi Cybersecurity] Audit ZIP: {zip_path}")
        print(f"[OpenKaipi Cybersecurity] Budget: spent ${ledger.spent:.2f} of "
              f"${ledger.monthly_limit_usd:.2f} this month.")

        return {
            "audit_dir": audit_dir,
            "zip_path": zip_path,
            "summary": counts,
            "total_findings": len(all_findings),
            "fingerprints": [f["fingerprint"] for f in all_findings],
        }
    finally:
        if brain_thread is not None and brain_thread.is_alive():
            brain_q.put(None)  # never leave the brain thread waiting after an error
        shutil.rmtree(workspace, ignore_errors=True)  # always clean the copy


def _executive_summary(source: str, stamp: str, counts: dict, findings: list[dict]) -> str:
    traffic = "RED" if counts["HIGH"] else ("YELLOW" if counts["MEDIUM"] else "GREEN")
    lines = [
        "# OpenKaipi Cybersecurity - Audit Summary",
        "",
        f"- **Status:** {traffic}",
        f"- **Target:** `{os.path.abspath(source)}`",
        f"- **Run:** {stamp}",
        f"- **Findings:** {len(findings)} "
        f"(HIGH: {counts['HIGH']}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})",
        "",
        "## Most urgent first",
        "",
    ]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    top = sorted(findings, key=lambda f: order.get(f["severity"], 9))[:10]
    if not top:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Weakness | Where | Engine |")
        lines.append("|----------|----------|-------|--------|")
        for f in top:
            lines.append(
                f"| {f['severity']} | {f['title']} | `{f['file']}:{f['line']}` | {f['engine']} |"
            )
    lines.append("")
    lines.append("See the other reports in this ZIP for every finding, "
                 "the attack story, and the fix.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def _manual_approvals(ask, label: str, brain):
    """Manual mode: nothing external or live happens without a typed 'y'.

    Returns the (possibly disabled) chatbot adapter, brain, and the set of
    approved probe names. With no interactive terminal everything is denied.
    """
    if not sys.stdin.isatty():
        print("[OpenKaipi Cybersecurity] Manual mode needs an interactive terminal. "
              "Live chatbot tests and the AI brain are OFF for this run.")
        return None, None, set()

    def yes(question: str) -> bool:
        return input(f"{question} [y/N] ").strip().lower() in {"y", "yes"}

    print("\n[OpenKaipi Cybersecurity] MANUAL MODE: nothing below runs unless you approve it.")
    if brain is not None and not yes(
            "Send MASKED finding snippets to Claude? (It costs money and the data leaves this computer.)"):
        brain = None
    allowed: set[str] = set()
    if ask is not None:
        print(f"\nLive tests on {label}. Each test sends one harmless message:")
        for name, message, *_rest in chatbot_auditor.PROBES:
            print(f"\n  Probe: {name}\n  Message: {message}")
            if yes("  Run this test?"):
                allowed.add(name)
        if not allowed:
            ask = None
    print()
    return ask, brain, allowed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OpenKaipi Cybersecurity - run a full audit on a copy of your code."
    )
    parser.add_argument("source", help="Folder or .zip with your code.")
    parser.add_argument(
        "--authorize",
        action="store_true",
        help="Confirm you own or are allowed to test this target. Required.",
    )
    parser.add_argument("--out", default="./reports", help="Where to write reports.")
    parser.add_argument("--budget", type=float, default=100.0,
                        help="Monthly budget cap in USD (default 100).")
    parser.add_argument("--est-cost", type=float, default=0.0,
                        help="Estimated cost of this run in USD (default 0).")
    parser.add_argument("--chatbot-url", help="Also probe a chatbot you own at this URL.")
    parser.add_argument("--chatbot-demo", action="store_true",
                        help="Also probe the built-in weak demo bot (for trying it out).")
    parser.add_argument("--brain", action="store_true",
                        help="Use Claude to review findings, explain them and suggest fixes "
                             "(needs ANTHROPIC_API_KEY; sends masked snippets to the API).")
    parser.add_argument("--brain-model", default=brain_mod.DEFAULT_MODEL)
    parser.add_argument("--brain-run-cap", type=float, default=2.0,
                        help="Max AI spend for one run in USD (default 2).")
    parser.add_argument("--notify", help="Send urgent findings to your phone/email: "
                        "ntfy:<topic> or email:<address> (see notifier.py).")
    parser.add_argument("--manual", action="store_true",
                        help="Ask for your OK before anything leaves your computer or "
                             "touches a live chatbot.")
    parser.add_argument("--request-field", default="message")
    parser.add_argument("--reply-field", default="reply")
    args = parser.parse_args(argv)

    if not args.authorize:
        print(
            "Not running: --authorize is missing.\n"
            "OpenKaipi Cybersecurity only tests code you own, or a test setup you have "
            "permission to test. Run again with --authorize.",
            file=sys.stderr,
        )
        return 2

    if not (os.path.isdir(args.source) or zipfile.is_zipfile(args.source)):
        print(f"Error: '{args.source}' is not a folder or a .zip file.", file=sys.stderr)
        return 2

    try:
        ask, label = None, "live-bot"
        if args.chatbot_demo:
            ask, label = chatbot_auditor.demo_bot(), "demo-bot"
        elif args.chatbot_url:
            ask = chatbot_auditor.http_bot(
                args.chatbot_url, args.request_field, args.reply_field)
            label = args.chatbot_url
        brain = None
        if args.brain:
            brain = brain_mod.Brain(model=args.brain_model, max_run_cost=args.brain_run_cap)
        allowed_probes = None
        if args.manual:
            ask, brain, allowed_probes = _manual_approvals(ask, label, brain)
        notifier = notifier_mod.parse_spec(args.notify) if args.notify else None
        result = run_audit(
            args.source, out_dir=args.out, budget=args.budget, est_cost=args.est_cost,
            chatbot_ask=ask, chatbot_label=label, brain=brain,
            notifier=notifier, allowed_probes=allowed_probes,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"[OpenKaipi Cybersecurity] {exc}", file=sys.stderr)
        return 3

    return 1 if result["summary"]["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
