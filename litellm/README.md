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
