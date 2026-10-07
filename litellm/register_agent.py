"""Register an agent in LiteLLM and give it its own virtual key.

Runs INSIDE the litellm container so the master key never leaves it. Reads a JSON spec on stdin, prints
the new key on stdout (redirect it straight into a mode-600 file; never echo it). Re-running replaces
the agent's key (old key with the same alias is deleted) and updates the agent card.

Usage (on the LiteLLM host, .101):
    umask 077
    sudo podman cp register_agent.py litellm:/tmp/register_agent.py
    echo '{"alias": "labwatch-agent", "title": "Lab Health Watch (labwatch-agent)",
           "description": "Daily 06:15 lab health briefing ...",
           "skills": [["health-snapshot", "Lab health snapshot", "Collect up/alerts/disk/..."]]}' \
      | sudo podman exec -i litellm python3 /tmp/register_agent.py > ~/labwatch.key

Spec fields: alias (also the key alias), title, description, skills [[id, name, description], ...],
optional models (default ["qwen3.8-27b"]), rpm_limit (30), max_parallel_requests (1),
optional opt_out_guardrails (e.g. ["basic-safety-filter"]).
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://localhost:4000"
MASTER = os.environ["LITELLM_MASTER_KEY"]


def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + MASTER, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:300]


spec = json.load(sys.stdin)
alias = spec["alias"]
models = spec.get("models", ["qwen3.8-27b"])

card = {
    "agent_name": alias,
    "agent_card_params": {
        "name": spec["title"], "description": spec["description"], "version": "1.0.0",
        "capabilities": {"streaming": False}, "defaultInputModes": ["text"], "defaultOutputModes": ["text"],
        "skills": [{"id": i, "name": n, "description": d, "tags": ["lab-ops"]} for i, n, d in spec.get("skills", [])],
    },
    "object_permission": {"models": models},
}
status, agents = api("GET", "/v1/agents")
existing = next((a for a in agents if a.get("agent_name") == alias), None) if status == 200 else None
status, res = api("PUT", f"/v1/agents/{existing['agent_id']}", card) if existing else api("POST", "/v1/agents", card)
if status != 200:
    sys.exit(f"agent register failed: {status} {res}")
agent_id = existing["agent_id"] if existing else res["agent_id"]

status, listed = api("GET", "/key/list?key_alias=" + urllib.parse.quote(alias))
if status == 200 and listed.get("keys"):
    api("POST", "/key/delete", {"keys": listed["keys"]})

metadata = {"purpose": spec["description"][:120], "tags": [alias]}
if spec.get("opt_out_guardrails"):
    metadata["opted_out_global_guardrails"] = spec["opt_out_guardrails"]
status, key = api("POST", "/key/generate", {
    "key_alias": alias, "models": models, "agent_id": agent_id,
    "rpm_limit": spec.get("rpm_limit", 30), "max_parallel_requests": spec.get("max_parallel_requests", 1),
    "metadata": metadata})
if status != 200:
    sys.exit(f"key/generate failed: {status} {key}")
print(f"{alias}: agent {agent_id[:8]}, key ...{key['key'][-4:]}", file=sys.stderr)
print(key["key"])
