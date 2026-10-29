# Vulnerability check

Finds common security problems in a copy of your code, such as injection, unsafe commands, and weak crypto.

```
python vuln_analyzer.py ./copy-of-your-project
```

## How to use it

1. Copy `tools/cybersecurity/scripts/vuln_analyzer.py` into a folder. This file runs alone.
2. You need Python 3.8 or newer. Do not install a package.
3. Make a copy of your project. The script only reads files. It does not run your program.
4. Open a terminal in the folder where you put the script. Run the command above. Change the path to your copy.
5. Open the Markdown report in `./reports/`. Each finding has an attack story and a fix.

Add `--out ./reports` at the end if you want a different report folder.

## Example output

A small test file that called `os.system` prints lines like these:

> [OpenKaipi Cybersecurity] Analyzing: /home/me/copy-of-your-project
> [OpenKaipi Cybersecurity] Done. 1 finding(s): HIGH=1 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] Report (Markdown): ./reports/vuln_report_20261029_190241.md
> [OpenKaipi Cybersecurity] Report (JSON):     ./reports/vuln_report_20261029_190241.json

The report table had this row:

> | 1 | HIGH | Dangerous OS Command (os.system) | `app.py` | 4 |
