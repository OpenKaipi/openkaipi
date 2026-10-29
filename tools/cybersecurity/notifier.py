#!/usr/bin/env python3
"""
OpenKaipi Cybersecurity - Notifier

Sends urgent findings to your phone or email, so you do not need to watch
the terminal. Findings that come close together go in ONE message. If a
scan finds eight urgent problems, you get one message, not eight.

Channels
--------
  ntfy:<topic>        Free push notifications. Install the ntfy app and
                      subscribe to your topic. Anyone who knows the topic
                      can read it, so use a long random one (10+ characters).
                      Set OPENKAIPI_NTFY_SERVER to use your own server.
  email:<address>     Email with your own SMTP account. Set these variables:
                      OPENKAIPI_SMTP_HOST, OPENKAIPI_SMTP_USER, OPENKAIPI_SMTP_PASSWORD,
                      and optional OPENKAIPI_SMTP_PORT (587) and OPENKAIPI_SMTP_FROM.

Privacy
-------
Messages only have the severity, problem name, file and line. They never
have code, secret values or AI text.

If sending fails, the audit does not stop. It prints a warning and continues.
Uses only the Python standard library.
"""

from __future__ import annotations

import os
import re
import smtplib
import sys
import threading
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Callable

MAX_LINES = 6
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _warn(msg: str) -> None:
    print(f"[OpenKaipi Cybersecurity] Notification problem: {msg}", file=sys.stderr)


def _ascii(text: str) -> str:
    return text.encode("ascii", "ignore").decode("ascii")


# --------------------------------------------------------------------------- #
# Senders: (title, body, urgent) -> None
# --------------------------------------------------------------------------- #

def ntfy_sender(topic: str) -> Callable[[str, str, bool], None]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{10,64}", topic):
        raise ValueError(
            "ntfy topic must be 10-64 letters, digits, '-' or '_' "
            "(use a long random one, because anyone who knows it can read your alerts)."
        )
    server = os.environ.get("OPENKAIPI_NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    parsed = urllib.parse.urlparse(server)
    if parsed.scheme != "https" and parsed.hostname not in LOCAL_HOSTS:
        raise ValueError("OPENKAIPI_NTFY_SERVER must use https:// (http only for localhost).")

    def send(title: str, body: str, urgent: bool) -> None:
        req = urllib.request.Request(
            f"{server}/{topic}",
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Title": _ascii(title),
                "Priority": "urgent" if urgent else "default",
                "Tags": "rotating_light" if urgent else "information_source",
            },
        )
        with urllib.request.urlopen(req, timeout=10):  # noqa: S310
            pass

    return send


def email_sender(to_addr: str) -> Callable[[str, str, bool], None]:
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", to_addr):
        raise ValueError(f"'{to_addr}' does not look like an email address.")
    host = os.environ.get("OPENKAIPI_SMTP_HOST")
    user = os.environ.get("OPENKAIPI_SMTP_USER")
    password = os.environ.get("OPENKAIPI_SMTP_PASSWORD")
    if not (host and user and password):
        raise ValueError(
            "email needs OPENKAIPI_SMTP_HOST, OPENKAIPI_SMTP_USER and OPENKAIPI_SMTP_PASSWORD "
            "(set them as environment variables, never in code)."
        )
    port = int(os.environ.get("OPENKAIPI_SMTP_PORT", "587"))
    sender = os.environ.get("OPENKAIPI_SMTP_FROM", user)

    def send(title: str, body: str, urgent: bool) -> None:
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = sender
        msg["To"] = to_addr
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)

    return send


# --------------------------------------------------------------------------- #
# Grouping notifier
# --------------------------------------------------------------------------- #

class Notifier:
    """Collects urgent findings and sends them as one grouped message."""

    def __init__(self, send: Callable[[str, str, bool], None],
                 window: float = 2.0, label: str = "OpenKaipi Cybersecurity") -> None:
        self._send = send
        self._window = window
        self._label = label
        self._pending: list[dict] = []
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def add(self, finding: dict) -> None:
        with self._lock:
            self._pending.append(finding)
            if self._timer is None:
                self._timer = threading.Timer(self._window, self.flush)
                self._timer.daemon = True
                self._timer.start()

    def flush(self) -> None:
        with self._lock:
            batch, self._pending = self._pending, []
            self._timer = None
        if not batch:
            return
        n = len(batch)
        lines = [
            f"- [{f['severity']}] {f['title']} ({f['file']}:{f['line']})"
            for f in batch[:MAX_LINES]
        ]
        if n > MAX_LINES:
            lines.append(f"...and {n - MAX_LINES} more. See the audit ZIP.")
        title = f"{self._label}: {n} urgent finding{'s' if n != 1 else ''}"
        try:
            self._send(title, "\n".join(lines), True)
        except Exception as exc:  # noqa: BLE001 - alerts must never break an audit
            _warn(f"{type(exc).__name__}: {exc}")

    def close(self) -> None:
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self.flush()

    def send_text(self, title: str, body: str, urgent: bool = False) -> None:
        """One-off message (e.g. 'monthly budget reached')."""
        try:
            self._send(title, body, urgent)
        except Exception as exc:  # noqa: BLE001
            _warn(f"{type(exc).__name__}: {exc}")


def parse_spec(spec: str) -> Notifier:
    """Build a Notifier from 'ntfy:<topic>' or 'email:<address>'."""
    kind, _, value = spec.partition(":")
    if kind == "ntfy":
        return Notifier(ntfy_sender(value))
    if kind == "email":
        return Notifier(email_sender(value))
    raise ValueError("--notify must look like ntfy:<topic> or email:<address>")


if __name__ == "__main__":
    # Quick check that alerts reach you:  python notifier.py ntfy:<your-topic>
    if len(sys.argv) != 2:
        print("Usage: python notifier.py ntfy:<topic>   (or email:<address>)")
        raise SystemExit(2)
    try:
        test = parse_spec(sys.argv[1])
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    test._send("OpenKaipi Cybersecurity test", "If you can read this, alerts work.", False)  # noqa: SLF001
    print("Test message sent. Check your phone. If nothing comes, check the topic name.")
