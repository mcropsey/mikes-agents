# agentdemo-agent

Part of [mikes-agents](../README.md). A **safe agent and a hijacked agent, side by side** — the demo for
"AI agents are API clients you have to monitor." Both personas drive the **same** lab MCP tools (the
`crapi-mcp` server on `.102`, which fronts the crAPI training app) through LiteLLM, so each shows up in LiteLLM
as its own agent identity and each produces API traffic your sensor + monitoring can see.

| Persona | LiteLLM agent | What it does |
|---|---|---|
| baseline | `agentdemo-baseline` | A normal user's workflow: sign up / log in, read **its own** dashboard and vehicle, browse the catalog. A few calls, all scoped to its own account. |
| hijacked | `agentdemo-anomaly` | The same assistant given a task whose **data contains an injected instruction** (a prompt-injection demo). A compromised agent then enumerates **other** users' objects and bulk-reads — the access pattern you want telemetry to light up on. |

After both runs it compares the two call traces (flagging cross-account/bulk calls) and pulls what the lab's
Loki captured in the window, into one report.

> Runs against **your own training lab only** (`crapi.cropseyit.com` via its MCP server). crAPI is deliberately
> vulnerable and built for exactly this kind of exercise.

## Run

```bash
agentdemo --scripted            # deterministic tool sequences, NO LLM (reliable traffic for a live demo)
agentdemo                       # LLM-driven: the model chooses the MCP calls (uses the GPU)
agentdemo --only hijacked       # just one persona
agentdemo --scripted --no-email
```

Not scheduled — it's a demo you run on demand. `--scripted` is the dependable choice in front of an audience;
`--agent` (default) is the real thing and needs the GPU, so expect it to be slower during interactive hours.

## Talking points

See [TALKING-POINTS.md](../TALKING-POINTS.md) for the narration (safe vs hijacked, where to point in LiteLLM
and Grafana, what the sensor sees).

## LiteLLM

Two keys so the personas are attributed separately: `AGENTDEMO_BASELINE_KEY` (alias `agentdemo-baseline`) and
`AGENTDEMO_ANOMALY_KEY` (alias `agentdemo-anomaly`), both opted out of `basic-safety-filter`. See
[litellm/](../litellm/).

## Config (env file)

`AGENTDEMO_MCP_URL` (default `http://192.168.1.102:8009/mcp`), `AGENTDEMO_MCP_AUTH` (blank unless the MCP server
requires a bearer token), shared `LOKI_URL`.

## Reports & Grafana

`/opt/labagents/data/reports/agentdemo/`, listed at `:9440/reports/#agentdemo`; metrics
`mikes_agentdemo_calls` / `mikes_agentdemo_sensitive` (by persona) and report logs via [agenthub](../agenthub/)
(dashboard *Agent Lab · Agents II* — the "baseline vs hijacked cross-account calls" tiles are the money shot).

The MCP transport is a tiny stdlib+httpx client, [`labagents/mcpclient.py`](../lab-agents-common/labagents/mcpclient.py).
