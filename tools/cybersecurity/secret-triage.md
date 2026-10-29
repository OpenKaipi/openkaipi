# Secret triage

Attach this page to your AI chat so it runs the secret scanner on a copy of your code and walks you through each finding.

```
You are helping me find secrets left in my code with OpenKaipi Cybersecurity.
Follow these rules for this whole chat:

1. Work only on a COPY of my project. Never on the only original.
2. Tell me to run exactly this command from the folder that holds the script:
   python secret_scanner.py ./copy-of-your-project
   To choose the report folder, add: --out ./reports
3. Exit code 0 = no HIGH findings. 1 = at least one HIGH finding. 2 = the path is not a folder.
4. When I paste the Markdown report from ./reports/, go through the findings
   from HIGH to MEDIUM to LOW. For each one give: file and line, type,
   and one concrete next step (rotate the key, move it to an environment
   variable or secret manager, or mark it as a false positive and say why).
5. Treat every HIGH finding as leaked. Tell me to rotate it, even if it is
   removed from the code, because it may still be in git history.
6. Never ask me to paste the full secret. Work only with the masked value.
7. Do not invent findings. If the report has none, say so.
```

## How to use it

1. Copy `tools/cybersecurity/scripts/secret_scanner.py` into a folder. It runs alone.
2. You need Python 3.8 or newer. It uses only the standard library. Do not install a package.
3. Make a copy of your project. Change `./copy-of-your-project` to the path of that copy.
4. Attach this page to your AI chat, or paste the block above. Run the command in a terminal.
5. Paste the Markdown report from `./reports/` into the chat. The script does not change your files and sends nothing over the network.

## Example output

A copy with one fake AWS key in `app.py` prints:

> [OpenKaipi Cybersecurity] Scanning: /tmp/demo/copy-of-your-project
> [OpenKaipi Cybersecurity] Done. 1 finding(s): HIGH=1 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] Report (Markdown): ./reports/secrets_report_20261029_123150.md
> [OpenKaipi Cybersecurity] Report (JSON):     ./reports/secrets_report_20261029_123150.json

The report row and the advice it gives:

> | 1 | HIGH | AWS Access Key ID | `app.py` | 3 | `AKI**************PL0` |
>
> - **What to do:** Change (rotate) this AWS key now and remove it from the code.

The AI then turns each row into a next step. Its wording varies (illustrative).
