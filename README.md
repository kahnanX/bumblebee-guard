# bumblebee-guard

Supply-chain guard plugin for [Hermes Agent](https://hermes-agent.nousresearch.com).
Wraps the local [Bumblebee](https://github.com/perplexityai/bumblebee) scanner
bridge with Hermes tools, a rate-limited context-injection hook, a slash
command and a bundled triage skill.

Bumblebee inventories installed packages (npm, PyPI, Go, RubyGems, Composer),
MCP server configs and editor/browser extensions, and exact-matches every
`(ecosystem, name, version)` against curated catalogs of known-compromised
packages (Shai-Hulud variants, gemstuffer, node-ipc stealer, …). An optional
OSV layer matches installed versions against OSV.dev advisories.

## What it does

- **`bumblebee_guard_scan`** — run a full read-only scan (no sudo, no package
  managers executed). 1–4 minutes.
- **`bumblebee_guard_status`** — latest results without re-scanning: curated
  findings, new-since-last, OSV count, packages inventoried, catalogs loaded.
- **`bumblebee_guard_diff`** — diff curated findings against a stored baseline
  (`show`) or set the current state as baseline (`set_baseline`).
- **`pre_llm_call` hook** — when the latest scan has curated findings, injects
  a one-line alert into the agent's context. Rate-limited to once per hour.
  **Never injects when clean** — zero context cost in the normal case.
- **`/bumblebee`** — slash command: `status` (default) | `scan` |
  `diff [show|set_baseline]` | `help`.
- **Bundled `triage` skill** — how to interpret findings: curated matches are
  high-confidence; OSV advisories need dedup and applicability checks;
  documented false-positive pattern (scanner fixtures containing
  threat-intel strings).

## Requirements

- Hermes Agent >= 0.21.6
- The Bumblebee bridge deployed at `~/.local/share/hermes-bumblebee-bridge/` —
  installed from
  [Deconstruct2021/hermes-bumblebee-bridge](https://github.com/Deconstruct2021/hermes-bumblebee-bridge)
  (maintained by @Deconstruct2021; this plugin is tested against commit
  `d89dd95`, bridge v0.1.0). Without it, tools
  report `bridge not deployed` cleanly — they never fail silently.
- Python stdlib only. No credentials, no `requires_env`.

## Configuration (`plugins.entries.bumblebee-guard.settings`)

| Key | Default | Meaning |
|---|---|---|
| `bridge_dir` | `~/.local/share/hermes-bumblebee-bridge` | Bridge install dir |
| `scan_timeout_s` | `240` | Scan timeout |
| `inject_status` | `true` | Enable the context injection hook |
| `osv_enabled` | `true` | Include OSV advisory counts in reports |

## Install

```bash
hermes plugins install <owner>/bumblebee-guard
hermes plugins enable bumblebee-guard
```

## Disclosure (catalog rule 13)

- The plugin itself makes **no network calls** and holds **no credentials**.
- The wrapped bridge's scan makes its own calls: the optional OSV layer
  queries OSV.dev; an optional, off-by-default catalog refresh fetches
  threat-intel JSON from the upstream Bumblebee repository.
- Scans run `daily_scan.sh` as the current user (no sudo) and read package
  metadata in `$HOME`; they never read `.env`/token files and never execute
  package managers.
- Scan durations up to ~3 minutes; the tool honors `scan_timeout_s` and
  reports timeouts instead of hanging the agent. Cron/unattended runs are
  unaffected: the hook never blocks turns.

## Tests

```bash
python3 -m pytest tests/ -q
```

## License

MIT
