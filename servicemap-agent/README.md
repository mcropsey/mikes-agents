# servicemap-agent: lab service map

Part of [mikes-agents](../README.md). Every morning at **05:40** it logs into every host Grafana monitors, inventories
everything that runs there, has the local model label each component, and publishes a map to Grafana and to
[cropsey-lab/service-map](https://github.com/mcropsey/cropsey-lab/tree/main/service-map).

```
05:40 servicemap.service (oneshot, three steps)
  1  servicemap_collect.py  (host, as mcropsey)  ──ssh + sudo -n──► every Prometheus up{job="node"} target
       systemd + user units, timers, cron, podman (rootless + root), docker, k3s/microk8s workloads,
       long-running scripts outside any service, TCP listeners + connections (tagged with their cgroup),
       lab endpoints in each service's Environment/env-file          ──► data/servicemap/raw/latest.json
  2  labagents.servicemap   (podman, own LiteLLM key) ──► LiteLLM .101:4000 ──► qwen3.8-27b on .194
       components + dependency edges, category/purpose labels (cached), host roles, diff vs yesterday
                                                                    ──► data/servicemap/site/*
  3  servicemap_publish.sh  (host, as mcropsey) ──git push──► cropsey-lab/service-map/ (only if the map changed)

servicemap-web.service  python http.server :9440 ──► data/servicemap/site/  (page, SVGs, /metrics)
```

## What it produces

| File (in `/opt/labagents/data/servicemap/site/`, served at `http://192.168.1.98:9440/`) | Use |
|---|---|
| `index.html` | Interactive map: stat tiles, changes since yesterday, fleet map (host cards with a chip per component), AI dependency diagram, all dependencies, Kubernetes workloads, per-host inventory. Filter box, category toggles, "show OS baseline". `?theme=dark` / `?theme=light` force a theme. |
| `fleet-{dark,light}.svg`, `ai-map-{dark,light}.svg` | Standalone images of the two diagrams (Grafana Text panels can show `<img>`; they strip iframes) |
| `metrics` | Prometheus exposition: `servicemap_component_info`, `servicemap_edge_info`, `servicemap_components`, `servicemap_hosts`, `servicemap_changes`, `servicemap_last_run_timestamp_seconds` |
| `README.md`, `servicemap.json` | GitHub view (mermaid diagram + tables) and the published model |

Also: `data/servicemap/history/<stamp>.json` (one per run), `data/reports/servicemap/` (like the other agents), and an
email **only when something changed** (no email on the first run or on quiet days).

## Categories

`AI agents` · `AI platform` · `Observability` · `API security` · `Network & ingress` · `Ops & CI` · `Platform & data` ·
`Lab target apps`, plus an `ai` flag for anything that uses or serves an LLM. Colours are the 8-slot categorical palette,
checked for colour-blind separation in light and dark. Distro services (sshd, chronyd, NetworkManager, podman healthcheck
timers, run-parts cron, ...) are marked **baseline**: hidden by default, never sent to the model, ignored in diffs.

## Dependencies (edges)

* **observed**: established TCP connections at collection time; the client's cgroup names the service/container,
  the server port is matched to the component listening on it (container port maps, listener cgroups, k8s NodePorts).
* **configured**: `host:port` URLs in a service's `Environment=` or `--env-file` / `EnvironmentFile=` (e.g. the lab agents
  -> LiteLLM `.101:4000`, LiteLLM -> LM Studio `.194:1234`, mcp-heartbeat -> crapi-mcp `.102:8009`). Only `host:port` is kept.
* **declared**: optional `/opt/labagents/data/servicemap/extra-edges.conf`, lines like
  `192.168.1.101/podman-root/root/litellm -> 192.168.1.194:1234` (component id from `servicemap.json`).

## Secrets and what gets published

The collector never keeps full command lines for anything published: services keep the program + script path, cron
keeps the command after a redaction pass (`key=***`, `--password ***`, bearer tokens, `user:pass@`, long random strings),
processes keep the script path only, containers keep image/ports/labels (no env). The GitHub repo is public, so the map
holds about the same detail as `lab-inventory.md`: hosts, service names, images, ports and schedules.

## LLM use

One key and registry entry, alias **`servicemap-agent`** (`SERVICEMAP_KEY` in `/opt/labagents/labagents.env`),
registered with [`../litellm/register_agent.py`](../litellm/) (skills `component-classify`, `host-roles`; guardrail opt-out
like the other agents). Labels are cached in `data/servicemap/classify-cache.json` by component signature, so a normal
morning asks the model only about new or changed components (first run: ~110 components in ~2.5 min; typical: 0-10 in
seconds). If the model is unavailable the rule-based labels are used and the page says so. `--reclassify` re-asks everything.

## Install (on .98)

```bash
cd ~/mikes-agents/servicemap-agent
sudo install -m 644 servicemap.py /opt/labagents/app/labagents/servicemap.py
sudo install -m 755 servicemap_collect.py servicemap_publish.sh /opt/labagents/app/
sudo install -m 755 servicemap /usr/local/bin/
sudo install -m 644 servicemap.service servicemap.timer servicemap-web.service /etc/systemd/system/
(cd /opt/labagents/app && sudo podman build -t localhost/labagents:latest .)
# LiteLLM key: see ../litellm/README.md (alias servicemap-agent, env var SERVICEMAP_KEY)
sudo firewall-cmd --permanent --add-port=9440/tcp && sudo firewall-cmd --reload
sudo systemctl daemon-reload && sudo systemctl enable --now servicemap-web.service servicemap.timer
servicemap            # first run: collect + label + publish
```

### Grafana

[`grafana/lab-service-map.json`](grafana/lab-service-map.json) is a provisioned dashboard ("Lab Service Map"): stat tiles,
the fleet map and AI map images (Text panels with `<img>`, which work with Grafana's default HTML sanitizer), a filterable
table of every component and a dependency table, plus a link to the interactive page. To install it, copy it into a new
folder under `/opt/monitoring/grafana/dashboards/` (each subfolder becomes a Grafana folder).

The stat and table panels read Prometheus; add this scrape job to `/opt/monitoring/prometheus/prometheus.yml` and reload:

```yaml
  - job_name: servicemap
    scrape_interval: 5m
    static_configs:
      - targets: ["192.168.1.98:9440"]
```

## Operate

| Task | Command |
|---|---|
| Run everything now | `servicemap` |
| One step | `servicemap collect` · `servicemap agent [--no-llm] [--reclassify] [--no-email]` · `servicemap publish [--force]` |
| One host only (partial snapshot, not used by the agent) | `servicemap collect --only 192.168.1.101` |
| Logs | `journalctl -u servicemap.service` |
| Change which hosts are skipped | `SERVICEMAP_EXCLUDE` (default `192.168.1.77,192.168.1.78`: rk3/rk4 are reserved) |

`publish` refuses to run if `~/cropsey-lab/service-map/` has uncommitted edits, and commits only that folder.
