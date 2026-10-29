#!/usr/bin/env python3
"""
OK Audit - Vulnerability Analyzer

This tool reads a COPY of your code and looks for common security
problems: injection, unsafe code execution, leaks of personal or
location data, weak crypto, insecure connections, and more.

For each problem it writes an "attack story" (what an attacker can do)
and a fix.

It is read-only and static. It only reads the code. It does not run it,
change it, or connect to any live system.

Use it only on your own code, or on a test project you have permission
to test.

Usage
-----
    python vuln_analyzer.py /path/to/copy-of-your-project
    python vuln_analyzer.py /path/to/copy-of-your-project --out ./reports

Uses only the Python standard library. Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Iterable

# --------------------------------------------------------------------------- #
# Configuration (shared conventions with the secret scanner)
# --------------------------------------------------------------------------- #

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".venv", "venv", "env", ".idea", ".vscode",
    ".next", ".nuxt", "coverage", ".cache", ".pytest_cache",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war",
    ".mp3", ".mp4", ".mov", ".avi", ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".o", ".a",
    ".db", ".sqlite", ".sqlite3", ".lock",
}

MAX_FILE_SIZE = 5 * 1024 * 1024
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Rule:
    """One vulnerability detection: name, regex, severity, attack story, fix."""
    name: str
    pattern: re.Pattern
    severity: str
    attack_story: str   # what an attacker could do
    fix: str            # how to close the hole


def _build_rules() -> list[Rule]:
    # (name, regex, severity, attack_story, fix)
    raw: list[tuple[str, str, str, str, str]] = [
        (
            "SQL Injection (string-built query)",
            r"(?i)(?:execute|executemany|query|raw)\s*\([^)]*(?:f['\"`]|['\"`]\s*\+|\+\s*['\"`]|\.format\s*\(|['\"`]\s*%|\$\{)",
            "HIGH",
            "An attacker types database commands into a normal field (like a "
            "search box) and reads or deletes ALL your data, including other "
            "users' bank keys.",
            "Use parameterized queries / prepared statements. Never glue user "
            "input directly into a query string.",
        ),
        (
            "OS Command Execution with shell=True",
            r"(?i)subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
            "HIGH",
            "If any user input reaches this line, an attacker can run their own "
            "commands on your server and take it over.",
            "Avoid shell=True. Pass arguments as a list and never build the "
            "command from user input.",
        ),
        (
            "Dangerous OS Command (os.system)",
            r"\bos\.system\s*\(",
            "HIGH",
            "Runs a system command directly. If user input reaches it, the "
            "attacker runs commands on your server.",
            "Replace with subprocess using an argument list, and keep user "
            "input out of it.",
        ),
        (
            "Code Execution (eval/exec)",
            r"\b(?:eval|exec)\s*\(",
            "HIGH",
            "Runs text as live code. If an attacker controls that text, they "
            "run their own program inside yours.",
            "Remove eval/exec. Parse data with safe parsers (e.g. JSON) instead.",
        ),
        (
            "JavaScript Code Execution (eval / new Function)",
            r"\b(?:eval|new\s+Function)\s*\(",
            "HIGH",
            "Runs text as live JavaScript. Attacker-controlled text becomes "
            "attacker-controlled code.",
            "Remove eval/new Function. Use JSON.parse or explicit logic.",
        ),
        (
            "Node Command Execution (child_process.exec)",
            r"child_process\.(?:exec|execSync)\s*\(",
            "HIGH",
            "Runs a shell command. If user input reaches it, the attacker runs "
            "commands on your server.",
            "Use execFile/spawn with an argument array and validate all input.",
        ),
        (
            "Insecure Deserialization (pickle/yaml/marshal)",
            r"(?:pickle\.loads?|marshal\.loads|yaml\.load)\s*\((?![^)]*Safe)",
            "HIGH",
            "Loading untrusted saved data this way can let an attacker run code "
            "just by sending you a crafted file or request.",
            "Use yaml.safe_load, or JSON. Never unpickle data from users.",
        ),
        (
            "TLS Verification Disabled",
            r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED)",
            "HIGH",
            "Turns off the check that you are really talking to your bank/API "
            "and not an impostor. Enables man-in-the-middle theft of the data.",
            "Never disable certificate verification. Fix the certificate chain "
            "instead.",
        ),
        (
            "Weak Password Hashing (md5/sha1)",
            r"(?i)(?:hashlib\.(?:md5|sha1)|\bmd5\s*\(|\bsha1\s*\()",
            "HIGH",
            "If your user database leaks, these weak hashes are cracked in "
            "minutes and every password (and bank-key unlock) is exposed.",
            "Hash passwords with bcrypt, scrypt, or Argon2 (with a salt).",
        ),
        (
            "Path Traversal (user input into file path)",
            r"(?i)(?:open|sendFile|readFile|read_file|createReadStream)\s*\([^)]*(?:req\.|request\.|params|query|args\.get|input\()",
            "HIGH",
            "An attacker asks for files like ../../secrets and reads files "
            "outside the intended folder, such as config with your keys.",
            "Validate and whitelist file names; resolve the path and confirm it "
            "stays inside the allowed folder.",
        ),
        (
            "Cross-Site Scripting sink (innerHTML / dangerouslySetInnerHTML)",
            r"(?i)(?:\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|v-html)",
            "MEDIUM",
            "If user text is placed here without cleaning, an attacker's script "
            "runs in other users' browsers and can steal their session.",
            "Render text safely (textContent / framework escaping) or sanitize "
            "HTML before inserting it.",
        ),
        (
            "Sensitive Data in Logs (password/token/location)",
            r"(?i)(?:console\.(?:log|info|debug)|print|logger?\.(?:info|debug|warn))\s*\([^)]*\b(?:password|passwd|pwd|secret|token|api[_-]?key|ssn|credit|latitude|longitude)\b",
            "MEDIUM",
            "Passwords, tokens, or live location end up in log files, where "
            "anyone with log access (or a leak) can read them.",
            "Never log secrets or precise location. Mask or remove them.",
        ),
        (
            "Precise Location Exposed in Response",
            r"(?i)(?:res\.(?:json|send)|return\s+jsonify|response\.json)\s*\([^)]*\b(?:latitude|longitude|\blat\b|\blng\b|\blon\b|coords?)\b",
            "MEDIUM",
            "Exact coordinates are sent out in an API response. Without strict "
            "access control, one user can track another's precise location.",
            "Only return location to authorized viewers; consider reducing "
            "precision (e.g. approximate area) when possible.",
        ),
        (
            "Permissive CORS (allow any origin)",
            r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]",
            "MEDIUM",
            "Any website can call your API from a victim's browser, which can "
            "help an attacker ride a logged-in user's session.",
            "Allow only your own trusted domains, especially when credentials "
            "are involved.",
        ),
        (
            "Weak Randomness for Tokens (Math.random / random)",
            r"(?i)(?:Math\.random\s*\(|[^.\w]random\.random\s*\()",
            "LOW",
            "If this randomness is used to create tokens or password resets, an "
            "attacker can predict them and hijack accounts.",
            "Use a cryptographically secure generator (secrets module, "
            "crypto.randomBytes).",
        ),
        (
            "Debug Mode Enabled",
            r"(?i)(?:debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1)",
            "MEDIUM",
            "Debug mode can show attackers your code and, in some frameworks, "
            "let them run commands through the error page.",
            "Disable debug in anything that is reachable by others.",
        ),
    ]
    return [Rule(n, re.compile(p), s, story, fix) for (n, p, s, story, fix) in raw]


RULES = _build_rules()

# Lines that are clearly comments or safe examples are skipped to cut noise.
COMMENT_PREFIXES = ("#", "//", "*", "/*", "<!--")


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    code: str
    attack_story: str
    fix: str
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        if not self.fingerprint:
            basis = f"{self.rule}|{self.file}|{self.line}"
            self.fingerprint = hashlib.sha1(basis.encode()).hexdigest()[:12]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def is_probably_text(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as fh:
            if b"\x00" in fh.read(1024):
                return False
    except OSError:
        return False
    return True


def iter_source_files(root: str) -> Iterable[str]:
    for dirpath, dirnames, filenames in os.walk(root):
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


def trim(code: str, limit: int = 160) -> str:
    code = code.strip()
    return code if len(code) <= limit else code[:limit] + " ..."


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def analyze_project(root: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(root):
        rel = os.path.relpath(path, root)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    if len(line) > 4000:
                        continue
                    stripped = line.strip()
                    if stripped.startswith(COMMENT_PREFIXES):
                        continue
                    for rule in RULES:
                        if rule.pattern.search(line):
                            findings.append(
                                Finding(
                                    rule=rule.name,
                                    severity=rule.severity,
                                    file=rel,
                                    line=line_no,
                                    code=trim(line),
                                    attack_story=rule.attack_story,
                                    fix=rule.fix,
                                )
                            )
        except OSError:
            continue

    unique = {f.fingerprint: f for f in findings}
    return sorted(
        unique.values(),
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line),
    )


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def write_reports(
    findings: list[Finding],
    target: str,
    out_dir: str,
    tool_name: str = "Vulnerability Analyzer",
    file_prefix: str = "vuln_report",
) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(out_dir, f"{file_prefix}_{stamp}.json")
    md_path = os.path.join(out_dir, f"{file_prefix}_{stamp}.md")

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    payload = {
        "tool": f"OK Audit - {tool_name}",
        "scanned_target": os.path.abspath(target),
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "summary": counts,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    lines = [
        f"# OK Audit - {tool_name} Report",
        "",
        f"- **Target:** `{os.path.abspath(target)}`",
        f"- **Generated:** {payload['generated_at']}",
        f"- **Findings:** {len(findings)} "
        f"(HIGH: {counts['HIGH']}, MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})",
        "",
        "> Each finding has an **attack story** (what an attacker can do) "
        "and a **fix**.",
        "",
    ]
    if not findings:
        lines.append("No common security problems found.")
    else:
        lines.append("| # | Severity | Weakness | File | Line |")
        lines.append("|---|----------|----------|------|------|")
        for i, f in enumerate(findings, start=1):
            lines.append(f"| {i} | {f.severity} | {f.rule} | `{f.file}` | {f.line} |")
        lines.append("")
        lines.append("## Details")
        lines.append("")
        for i, f in enumerate(findings, start=1):
            lines.append(f"### {i}. [{f.severity}] {f.rule}")
            lines.append(f"- **File:** `{f.file}` (line {f.line})")
            lines.append(f"- **Code:** `{f.code}`")
            lines.append(f"- **Attack story:** {f.attack_story}")
            lines.append(f"- **Fix:** {f.fix}")
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
        description="OK Audit - find vulnerabilities in a copy of your code."
    )
    parser.add_argument("target", help="Folder with a COPY of your code.")
    parser.add_argument("--out", default="./reports", help="Where to write reports.")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.target):
        print(f"Error: '{args.target}' is not a folder.", file=sys.stderr)
        return 2

    print(f"[OK Audit] Analyzing: {os.path.abspath(args.target)}")
    findings = analyze_project(args.target)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    md_path, json_path = write_reports(findings, args.target, args.out)

    print(f"[OK Audit] Done. {len(findings)} finding(s): "
          f"HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    print(f"[OK Audit] Report (Markdown): {md_path}")
    print(f"[OK Audit] Report (JSON):     {json_path}")
    return 1 if counts["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
