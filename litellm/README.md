# LiteLLM registration

Part of [mikes-agents](../README.md). Every agent gets **its own virtual key** and **its own entry in the
LiteLLM agent registry** (UI → *Agents*), linked by `agent_id`, so traffic and spend are attributed per agent.

LiteLLM runs on **192.168.1.101** in the rootful podman container `litellm` (UI http://192.168.1.101:4000/ui).

## Key settings (all agents)

| Setting | Value | Why |
|---|---|---|
| `models` | `["qwen3.8-27b"]` | The only model the agent may call: other LM Studio models would load next to it and slow the GPU down |
| `max_parallel_requests` | 1 | One request in flight per agent |
| `rpm_limit` | 30 | Plenty for a scheduled job, stops runaway loops |
| `agent_id` | the agent's registry id | Attributes traffic to the agent |
| `metadata.opted_out_global_guardrails` | `["basic-safety-filter"]` | The lab-wide content filter blocks security vocabulary; only these keys skip it |

The guardrail opt-out is read only from admin-set key/team metadata. A caller can't set it in a request.

## Agents

| alias | title | env var on .98 |
|---|---|---|
| `secnews-agent` | Cybersecurity News Digest (secnews-agent) | `LITELLM_API_KEY` in `/opt/secnews/secnews.env` |
| `labwatch-agent` | Lab Health Watch (labwatch-agent) | `LABWATCH_KEY` in `/opt/labagents/labagents.env` |
| `cvewatch-agent` | CVE-to-Lab Matcher (cvewatch-agent) | `CVEWATCH_KEY` |
| `patchwatch-agent` | Patch & Image Drift Watch (patchwatch-agent) | `PATCHWATCH_KEY` |
| `servicemap-agent` | Lab Service Map (servicemap-agent) | `SERVICEMAP_KEY` (registered 2026-10-13) |
| `alertwatch-agent` | Alert Triage (alertwatch-agent) | `ALERTWATCH_KEY` |
| `weekrollup-agent` | Weekly Digest & Agent QA (weekrollup-agent) | `WEEKROLLUP_KEY` |
| `patchrun-agent` | Approved Patch Runner (patchrun-agent) | `PATCHRUN_KEY` |
| `agentdemo-baseline` | Agent Demo: Baseline (agentdemo-baseline) | `AGENTDEMO_BASELINE_KEY` |
| `agentdemo-anomaly` | Agent Demo: Hijacked (agentdemo-anomaly) | `AGENTDEMO_ANOMALY_KEY` |
| `llmredteam-probe` | LLM Guardrail Eval: Probe (llmredteam-probe) | `LLMREDTEAM_PROBE_KEY` |
| `llmredteam-judge` | LLM Guardrail Eval: Judge (llmredteam-judge) | `LLMREDTEAM_JUDGE_KEY` |

The seven agents above were registered **2026-10-19**. All opt out of `basic-safety-filter` **except
`llmredteam-probe`**, which keeps the guardrail on because it is the system under test (see
[llmredteam-agent/](../llmredteam-agent/)). `agentdemo` runs two personas under two keys so LiteLLM attributes
the safe and hijacked agents separately; `llmredteam` uses a probe key (guardrail on) and a judge key
(guardrail off).

## Guardrails

The lab's content guardrail is **LiteLLM-native**: a v2 guardrail named `basic-safety-filter`
(id `538513e8…`, stored in the DB, `store_model_in_db: true`) that BLOCKs harmful categories
(`harm_toxic_abuse`, `harmful_violence`, …) at `severity_threshold: medium`. It is applied globally; every
agent key opts out via `metadata.opted_out_global_guardrails: ["basic-safety-filter"]` **except**
`llmredteam-probe`, which keeps it on so the [llmredteam-agent](../llmredteam-agent/) can test it. The agents
themselves do **no** guardrailing of their own — everything is enforced at the gateway.

## Monitoring (guardrails + traffic) — added 2026-10-19

LiteLLM reports its own metrics to the lab Prometheus/Grafana; nothing custom in between.

- **Enabled** in `/opt/litellm/config.yaml` on `.101`:
  ```yaml
  litellm_settings:
    callbacks: ["prometheus"]                 # LiteLLM's native Prometheus integration (not license-gated in v1.104.0)
    require_auth_for_metrics_endpoint: false  # /metrics is public so Prometheus can scrape it (no secrets in it)
  ```
  then `sudo systemctl restart litellm` (backup: `config.yaml.bak-pre-prometheus-20261019`).
- **Scraped** by Prometheus on `.98` (`job_name: litellm`, `metrics_path: /metrics/` — `/metrics` 307-redirects —
  target `192.168.1.101:4000`). `/metrics` carries only aggregate operational data (request/token/spend/latency
  counts, key aliases), no prompts or secrets, and the lab is firewalled.
- **Dashboard:** *LiteLLM Gateway* (`/d/litellm-gateway`, folder **LiteLLM**), source copy
  [`grafana/litellm-gateway.json`](grafana/litellm-gateway.json), installed at
  `/opt/monitoring/grafana/dashboards/LiteLLM/litellm-gateway.json`.

Useful metrics (all labelled by `api_key_alias`, so everything is **per agent**):
`litellm_proxy_total_requests_metric_total` (by `status_code` — a **guardrail BLOCK is a 400**),
`litellm_proxy_failed_requests_metric_total`, `litellm_total_tokens_metric_total`, `litellm_spend_metric_total`,
`litellm_request_total_latency_metric_*`, and `litellm_overhead_with_guardrails_latency_metric_*` (guardrail
processing cost). This is *operational* guardrail monitoring (how often it fires, on which agent); llmredteam
covers *effectiveness* (does it catch bad prompts).

## Create or rotate a key

[`register_agent.py`](register_agent.py) runs inside the litellm container (the master key never leaves it),
creates or updates the registry entry, replaces any existing key with that alias, and prints the new key.

```bash
# on .101
umask 077
sudo podman cp register_agent.py litellm:/tmp/register_agent.py
cat > /tmp/spec.json <<'EOF'
{"alias": "labwatch-agent",
 "title": "Lab Health Watch (labwatch-agent)",
 "description": "Daily 06:15 lab health briefing from Prometheus/Loki/Alertmanager on .98; investigates with its own PromQL/LogQL tool calls.",
 "skills": [["health-snapshot", "Lab health snapshot", "Collect up/alerts/disk/memory/load/reboots"],
            ["prometheus-query", "Prometheus query tool", "PromQL instant and range queries"],
            ["loki-logs", "Loki log search tool", "Fetch and count log lines with LogQL"]],
 "opt_out_guardrails": ["basic-safety-filter"]}
EOF
sudo podman exec -i litellm python3 /tmp/register_agent.py < /tmp/spec.json > ~/labwatch.key
sudo podman exec litellm rm -f /tmp/register_agent.py; rm /tmp/spec.json

# copy into the env file on .98 without printing it
ssh 192.168.1.98 'k=$(cat); sudo sed -i "s|^LABWATCH_KEY=.*|LABWATCH_KEY=$k|" /opt/labagents/labagents.env' < ~/labwatch.key
rm ~/labwatch.key
```

Rotating a key invalidates the old one at once, so update the env file straight away.

## Add the guardrail opt-out to an existing key

```bash
sudo podman exec -i litellm python3 - <<'EOF'
import json, os, urllib.request
M = os.environ["LITELLM_MASTER_KEY"]
def api(m, p, b=None):
    r = urllib.request.Request("http://localhost:4000" + p, method=m, data=json.dumps(b).encode() if b else None,
                               headers={"Authorization": "Bearer " + M, "Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(r).read())
for k in api("GET", "/key/list?return_full_object=true&key_alias=labwatch-agent")["keys"]:
    meta = {**(k.get("metadata") or {}), "opted_out_global_guardrails": ["basic-safety-filter"]}
    api("POST", "/key/update", {"key": k["token"], "metadata": meta})
EOF
```
