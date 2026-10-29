# OpenKaipi

**Your AI can do more. Here's how.**

Make your AI feel OK.

## What it is

OpenKaipi is an MCP connector. It shows up inside the AI chat you already use.
From the chat, you can turn on, turn off, install, edit and create "agent tricks".
A trick is a reusable function or recipe that gives your AI a new way to work.

OpenKaipi works with any AI app that supports MCP. It is not tied to one brand. [TODO: list of AI apps we tested]

## How it works

1. You add the OpenKaipi connector to your AI chat. [TODO: setup steps]
2. The connector gives your AI tools to list, install, turn on, turn off, edit and create tricks.
3. Tricks come from the community catalog in this repo, or you write your own.
4. When a trick is on, your AI can use it in the chat.

Examples of tricks we want to have (not all exist yet, see [TODO: status]):

- Sub-missions: sub-agents that work in parallel on parts of a task.
- Fluid chatbots: [TODO: short definition].
- Agents that do not leak sensitive information.
- Stable remote daemons: [TODO: short definition].

## Repo structure

```
connector/   the MCP connector (comes later)
tricks/      the catalog of community tricks
tools/       tools you can run today (tools/audit: OK Audit)
docs/        documentation
```

Each trick lives in its own folder inside `tricks/`. Every trick has a `README.md` with the same fields:

- What it does
- Install
- Tested on
- Safety notes

To start a new trick, copy `tricks/_template/`. See [tricks/README.md](tricks/README.md).

## Quick start

Today you can run the audit tools. They need Python 3.8+.

```
python tools/audit/secret_scanner.py ./copy-of-your-project
```

Run it on a copy of your project. It is read-only and writes a report in `./reports/`. See [tools/audit/README.md](tools/audit/README.md).

The MCP connector comes later.

## Contribute

OpenKaipi is built in public by students. Everyone is welcome.
Read [CONTRIBUTING.md](CONTRIBUTING.md) to add a trick or fix something.
Please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
