# Full audit

Runs the secret check, the vulnerability check, and the chatbot audit together, then saves one ZIP.

```
python orchestrator.py ./copy-of-your-project --authorize
```

## How to use it

1. Copy every file in `tools/cybersecurity/scripts/` into one folder. This command uses the other scripts in that folder.
2. You need Python 3.8 or newer. Do not install a package.
3. `--authorize` is required. Use this only on code you own or may test.
4. The command can take a project folder or a `.zip` of your code. It makes a temporary copy and does not change the original.
5. Open a terminal in the folder where you put the scripts. Run the command above.
6. Urgent findings print right away. The ZIP is written under `./reports/`.

A static run costs nothing. `--budget` defaults to 100 USD per month and matters when you also turn on AI review.

## Example output

Part of a small test run looks like this:

> [OpenKaipi Cybersecurity] Copy is ready. The original was not changed.
> URGENT [HIGH] AWS Access Key ID -> app.py:3
> [OpenKaipi Cybersecurity] Audit done. HIGH=3 MEDIUM=0 LOW=0
> [OpenKaipi Cybersecurity] Audit ZIP: ./reports/openkaipi_cybersecurity_20261029_190244.zip
> [OpenKaipi Cybersecurity] Budget: spent $0.00 of $100.00 this month.

The ZIP has `EXECUTIVE_SUMMARY.md`. On that test it started with `Status: RED` and listed 3 HIGH findings.
