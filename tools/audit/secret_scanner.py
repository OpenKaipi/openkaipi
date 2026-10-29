#!/usr/bin/env python3
"""
OK Audit - Secret Scanner

This tool scans a COPY of your code. It looks for secrets that someone
left in the code by mistake: API keys, tokens, private keys, database
passwords. An attacker looks for these first.

It is read-only. It does not change your code. It writes a report
(Markdown and JSON) in ./reports/.

Use it only on your own code, or on a test project you have permission
to test.

Usage
-----
    python secret_scanner.py /path/to/copy-of-your-project

    # choose the report folder
    python secret_scanner.py /path/to/copy-of-your-project --out ./reports

Uses only the Python standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Iterable

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Directories we never look inside (dependencies, build output, version control).
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".idea", ".vscode",
    ".next", ".nuxt", "coverage", ".cache", ".pytest_cache",
}

# File extensions we treat as binary and skip (reading them is pointless/noisy).
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war",
    ".mp3", ".mp4", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".o", ".a",
    ".db", ".sqlite", ".sqlite3", ".lock",
}

# Skip very large files (in bytes). A 5 MB source file is almost always data.
MAX_FILE_SIZE = 5 * 1024 * 1024

# Severity levels, ordered so we can sort worst-first.
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Rule:
    """A single detection rule: a name, a compiled regex, and a severity."""
    name: str
    pattern: re.Pattern
    severity: str
    advice: str


# Each rule looks for one family of secret. Patterns are intentionally
# conservative to keep false positives low; the entropy check below catches
# the generic cases the named rules miss.
def _build_rules() -> list[Rule]:
    raw: list[tuple[str, str, str, str]] = [
        (
            "AWS Access Key ID",
            r"\bAKIA[0-9A-Z]{16}\b",
            "HIGH",
            "Change (rotate) this AWS key now and remove it from the code.",
        ),
        (
            "AWS Secret Access Key",
            r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
            "HIGH",
            "Rotate the AWS secret and move it to an environment variable.",
        ),
        (
            "Google API Key",
            r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "HIGH",
            "Restrict or rotate this Google API key and remove it from the code.",
        ),
        (
            "Private Key Block",
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            "HIGH",
            "A private key should never be in the code. Change it now.",
        ),
        (
            "Stripe Live Secret Key",
            r"\bsk_live_[0-9a-zA-Z]{24,}\b",
            "HIGH",
            "Change this Stripe live key in the Stripe dashboard now.",
        ),
        (
            "GitHub Token",
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b",
            "HIGH",
            "Revoke this GitHub token in your account settings.",
        ),
        (
            "GitHub Fine-grained PAT",
            r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
            "HIGH",
            "Revoke this GitHub personal access token.",
        ),
        (
            "Slack Token",
            r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b",
            "HIGH",
            "Revoke this Slack token in the Slack admin console.",
        ),
        (
            "SendGrid API Key",
            r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b",
            "HIGH",
            "Rotate this SendGrid key.",
        ),
        (
            "Twilio Account SID",
            r"\bAC[0-9a-fA-F]{32}\b",
            "MEDIUM",
            "Confirm this Twilio SID is not paired with a secret in the code.",
        ),
        (
            "JSON Web Token (JWT)",
            r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
            "MEDIUM",
            "If this token is long-lived, treat it as a leaked credential.",
        ),
        (
            "Database Connection String with Password",
            r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://"
            r"[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+",
            "HIGH",
            "Move this connection string (it has a password) to a secret store.",
        ),
        (
            "Generic Assigned Secret",
            r"(?i)\b(?:api[_-]?key|apikey|secret|token|passwd|password|pwd|"
            r"access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"][^'\"]{8,}['\"]",
            "MEDIUM",
            "Check if this is a real secret. If yes, move it to an environment variable.",
        ),
    ]
    return [Rule(n, re.compile(p), s, a) for (n, p, s, a) in raw]


RULES = _build_rules()

# Values that are obviously placeholders, not real secrets.
PLACEHOLDER_HINTS = (
    "example", "placeholder", "changeme", "change_me", "your_", "xxxx",
    "dummy", "sample", "test", "<", "{{", "redacted", "none", "null",
    "password", "secret", "token",  # bare words used as names, not values
)


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    masked_snippet: str
    advice: str
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        if not self.fingerprint:
            basis = f"{self.rule}|{self.file}|{self.line}|{self.masked_snippet}"
            self.fingerprint = hashlib.sha1(basis.encode()).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def shannon_entropy(value: str) -> float:
    """Estimate randomness of a string. Real keys look random (high entropy)."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask(secret: str) -> str:
    """Show only the first and last 3 characters so the report is safe to share."""
    secret = secret.strip().strip("'\"")
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}{'*' * (len(secret) - 6)}{secret[-3:]}"


def looks_like_placeholder(line: str) -> bool:
    low = line.lower()
    # Count placeholder hints; a line with many hint-words is likely a template.
    hits = sum(1 for hint in PLACEHOLDER_HINTS if hint in low)
    return hits >= 2 and "=" not in line and ":" not in line


def is_probably_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(1024)
        if b"\x00" in chunk:  # null byte -> binary
            return False
    except OSError:
        return False
    return True


def iter_source_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip-dirs in place so os.walk does not descend into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            if is_probably_text(full):
                yield full


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

def scan_line(rel_path: str, line_no: int, line: str) -> list[Finding]:
    findings: list[Finding] = []

    for rule in RULES:
        for match in rule.pattern.finditer(line):
            snippet = match.group(0)
            if looks_like_placeholder(snippet):
                continue
            findings.append(
                Finding(
                    rule=rule.name,
                    severity=rule.severity,
                    file=rel_path,
                    line=line_no,
                    masked_snippet=mask(snippet),
                    advice=rule.advice,
                )
            )

    # Entropy pass: catch high-randomness quoted strings the named rules missed.
    for quoted in re.findall(r"['\"]([A-Za-z0-9/+_\-=]{20,})['\"]", line):
        if any(f.masked_snippet == mask(quoted) for f in findings):
            continue
        if shannon_entropy(quoted) >= 4.0 and not looks_like_placeholder(quoted):
            findings.append(
                Finding(
                    rule="High-Entropy String (possible secret)",
                    severity="LOW",
                    file=rel_path,
                    line=line_no,
                    masked_snippet=mask(quoted),
                    advice="This looks random, like a key. Check if it is a secret.",
                )
            )

    return findings


def scan_project(root: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(root):
        rel = os.path.relpath(path, root)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    if len(line) > 4000:  # skip minified / data lines
                        continue
                    findings.extend(scan_line(rel, line_no, line))
        except OSError:
            continue

    # De-duplicate by fingerprint, then sort worst-first.
    unique = {f.fingerprint: f for f in findings}
    return sorted(
        unique.values(),
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line),
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def write_reports(findings: list[Finding], target: str, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = os.path.join(out_dir, f"secrets_report_{stamp}.json")
    md_path = os.path.join(out_dir, f"secrets_report_{stamp}.md")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    payload = {
        "tool": "OK Audit - Secret Scanner",
        "scanned_target": os.path.abspath(target),
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "summary": counts,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    lines = [
        "# OK Audit - Secret Scan Report",
        "",
        f"- **Target:** `{os.path.abspath(target)}`",
        f"- **Generated:** {payload['generated_at']}",
        f"- **Findings:** {len(findings)} "
        f"(HIGH: {counts['HIGH']}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})",
        "",
        "> Severity: **HIGH** = think of it as leaked, change it now. "
        "**MEDIUM** = probably a secret, check it. **LOW** = looks random, check it.",
        "",
    ]
    if not findings:
        lines.append("No secrets found.")
    else:
        lines.append("| # | Severity | Type | File | Line | Value (masked) |")
        lines.append("|---|----------|------|------|------|----------------|")
        for i, f in enumerate(findings, start=1):
            lines.append(
                f"| {i} | {f.severity} | {f.rule} | `{f.file}` | {f.line} | "
                f"`{f.masked_snippet}` |"
            )
        lines.append("")
        lines.append("## Details")
        lines.append("")
        for i, f in enumerate(findings, start=1):
            lines.append(f"### {i}. [{f.severity}] {f.rule}")
            lines.append(f"- **File:** `{f.file}` (line {f.line})")
            lines.append(f"- **Value (masked):** `{f.masked_snippet}`")
            lines.append(f"- **What to do:** {f.advice}")
            lines.append(f"- **Fingerprint:** `{f.fingerprint}`")
            lines.append("")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return md_path, json_path


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="OK Audit - scan a copy of your code for exposed secrets."
    )
    parser.add_argument("target", help="Folder with a COPY of your code.")
    parser.add_argument(
        "--out", default="./reports", help="Where to write reports (default: ./reports)."
    )
    args = parser.parse_args(argv)

    if not os.path.isdir(args.target):
        print(f"Error: '{args.target}' is not a folder.", file=sys.stderr)
        return 2

    print(f"[OK Audit] Scanning: {os.path.abspath(args.target)}")
    findings = scan_project(args.target)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    md_path, json_path = write_reports(findings, args.target, args.out)

    print(f"[OK Audit] Done. {len(findings)} finding(s): "
          f"HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    print(f"[OK Audit] Report (Markdown): {md_path}")
    print(f"[OK Audit] Report (JSON):     {json_path}")

    # Exit code 1 if anything HIGH was found, so automation can react later.
    return 1 if counts["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
