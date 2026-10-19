# weekrollup-agent

Part of [mikes-agents](../README.md). A weekly digest of every lab agent's reports **plus a quality check of
the agents themselves**. It reads the last N days (default 7) of saved report JSON from every agent, builds a
compact timeline, and asks the model for: the week's story, issues that recurred or stayed open, and a quality
section that flags reports contradicting the data (e.g. labwatch GREEN while a target was down, an "affected"
CVE finding with no action). Read-only — no inventory, no SSH.

## Run

| | |
|---|---|
| Schedule | `weekrollup.timer` → Fri 06:55 America/Chicago (after the morning agents) |
| Manual | `weekrollup [--days N] [--no-email] [--to ADDR]` |

secnews reports live under `/opt/secnews/` (root-only), so the unit bind-mounts them read-only at
`/secnews-reports` and sets `SECNEWS_REPORTS=/secnews-reports`.

## LiteLLM

Key `WEEKROLLUP_KEY`, alias `weekrollup-agent`, opted out of `basic-safety-filter`. See [litellm/](../litellm/).

## Reports & Grafana

`/opt/labagents/data/reports/weekrollup/`, listed at `:9440/reports/#weekrollup`; metrics
`mikes_weekrollup_open_items` / `mikes_weekrollup_quality_issues` and report logs via
[agenthub](../agenthub/) (dashboard *Agent Lab · Agents II*).
