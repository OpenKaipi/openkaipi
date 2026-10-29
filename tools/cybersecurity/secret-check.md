# Secret check

Finds API keys, tokens, private keys, and passwords left in a copy of your code.

```
python secret_scanner.py ./copy-of-your-project
```

## How to use it

1. Copy `tools/cybersecurity/scripts/secret_scanner.py` into a folder. This file runs alone.
2. You need Python 3.8 or newer. Do not install a package.
3. Make a copy of your project. Run the script on the copy, not on the only original.
4. Open a terminal in the folder where you put the script. Run the command above. Change the path to your copy.
5. Open the Markdown report in `./reports/`. The script does not change your files.

Add `--out ./reports` at the end if you want a different report folder.

## Example output

A small test file with one fake key prints lines like these:

> [OpenKaipi Cybersecurity] Scanning: /home/me/copy-of-your-project
> [OpenKaipi Cybersecurity] Done. 1 finding(s): HIGH=1 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] Report (Markdown): ./reports/secrets_report_20261029_190241.md
> [OpenKaipi Cybersecurity] Report (JSON):     ./reports/secrets_report_20261029_190241.json

The report table had this row:

> | 1 | HIGH | AWS Access Key ID | `app.py` | 3 | `AKI**************PLE` |

HIGH means treat it as leaked and change it. The report shows a masked value, not the full secret.
