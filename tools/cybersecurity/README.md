# OpenKaipi Cybersecurity

OpenKaipi Cybersecurity is a notebook of tricks that check a copy of your code.
Each trick is one page. Copy the code block. You do not install this notebook.
Scripts need Python 3.8 or newer and use only the Python standard library.
Copy a script file and run it. One optional script can call an AI model.
Run a trick only on code you own, or on a chatbot you may test.
Scripts read files. They do not change them. Reports go to `./reports/`.
Nothing leaves your computer unless you turn on AI review, notify, or a live test.

## Tricks

- [Secret check](secret-check.md) — find keys, tokens, private keys, and passwords in code
- [Secret triage](secret-triage.md) — attach to your AI chat to run the secret check and triage each finding
- [Vulnerability check](vuln-check.md) — find common security problems in code
- [Chatbot audit](chatbot-audit.md) — check a chatbot you own
- [Full audit](full-audit.md) — run the checks together and save one ZIP
- [AI review](ai-review.md) — ask an AI model to review the findings
- [Notify](notify.md) — send urgent findings to your phone or email
- [Schedule](schedule.md) — run the audit on a timer or when code changes
