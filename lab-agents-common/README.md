# lab-agents-common

Part of [mikes-agents](../README.md). Shared code and the container image for **labwatch-agent**,
**cvewatch-agent** and **patchwatch-agent**.

## Files

| File | Purpose |
|---|---|
| `labagents/common.py` | `Agent` class (OpenAI SDK client on the agent's own LiteLLM key, JSON answers with retry, tool-calling loop), lab host map, HTML helpers, report saving, Gmail sending, inventory loader |
| `labagents/__init__.py` | Package marker |
| `Containerfile` | `python:3.12-slim` + `openai` + `httpx`; entrypoint `python -m`, so the command is the module name |
| `labagents.env.example` | Env-file template (no secrets) |

## How the image is assembled

The image's `labagents` package is `common.py` plus each agent's module copied next to it:

```
/opt/labagents/app/
├── Containerfile
├── labinventory.py          (runs on the host, not in the image)
└── labagents/
    ├── __init__.py
    ├── common.py            <- lab-agents-common/labagents/
    ├── labwatch.py          <- labwatch-agent/
    ├── cvewatch.py          <- cvewatch-agent/
    └── patchwatch.py        <- patchwatch-agent/
```

```bash
sudo podman build -t localhost/labagents:latest -f /opt/labagents/app/Containerfile /opt/labagents/app
```

Containers run with `--network host` (Prometheus/Loki/Alertmanager on .98 and LiteLLM on .101 are reached
directly) and bind-mount `/opt/labagents/data` at `/data` with `:z` (shared SELinux label, because
labinventory on the host and several containers use the same directory).

## Environment (`/opt/labagents/labagents.env`, root:root 600)

| Variable | Example | Used by |
|---|---|---|
| `LITELLM_URL` | `http://192.168.1.101:4000/v1` | all |
| `MODEL` | `qwen3.8-27b` | all |
| `LABWATCH_KEY` / `CVEWATCH_KEY` / `PATCHWATCH_KEY` | `sk-...` | one per agent (see [../litellm](../litellm/)) |
| `PROM_URL` / `LOKI_URL` / `ALERTMANAGER_URL` | `http://192.168.1.98:9090` / `:3100` / `:9093` | labwatch |
| `MAIL_TO`, `SMTP_USER`, `SMTP_PASS` | Gmail address + app password | all |
| `DATA_DIR` | `/data` (default) | all |

The agent name decides which key is used: `Agent("labwatch-agent")` reads `LABWATCH_KEY`.

## What every request carries

- `Authorization: Bearer <agent key>` (attributes the request to the agent in LiteLLM)
- Headers `X-Agent-Name: <agent>` and `X-Agent-Host: 192.168.1.98`
- `user: <agent>@192.168.1.98` and `metadata.tags: [<agent>]` (show in LiteLLM spend logs)
- `max_tokens: 24000`: qwen3.8 reasons before answering and the reasoning counts against the limit.
  `ask_json` retries once if the answer is cut off or isn't valid JSON.

## Writing a new agent

```python
from .common import Agent, page, save_report, send_mail

agent = Agent("myagent-agent")                 # needs MYAGENT_KEY in the env file
result = agent.ask_json(SYSTEM_PROMPT, data)    # or agent.run_tools(SYSTEM, user, TOOLS, handlers)
body = page("Title", "<p>...</p>", agent.footer())
save_report("myagent", body, result)
send_mail("Subject", body)
```
