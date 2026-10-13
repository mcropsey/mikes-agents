# agenthub: report exporter for Grafana

Part of [mikes-agents](../README.md). **Not an LLM agent:** a small always-on service on .98 that turns each agent's
latest report into Prometheus metrics and Loki log lines, so the reports show up in Grafana.

```
reports/<agent>/<stamp>.json ──► agenthub.py (:9430, polls every 20 s)
                                   ├─ GET /metrics  ──► Prometheus job "agenthub" ──► Grafana stats/graphs
                                   └─ push new reports ──► Loki {agent, report, status} ──► Grafana report-log panels
```

| Agent | Metrics (`mikes_*`) | Loki lines |
|---|---|---|
| labwatch | status code/label, issues by severity, healthy checks | status + headline, summary, one line per issue |
| cvewatch | findings by verdict, affected by severity, CVEs matched | summary, one line per finding, stats |
| patchwatch | items by priority, hosts with updates, advisories | headline, summary, one line per priority |
| secnews | stories (by severity), KEV notes present | headline, summary, one line per story, KEV notes |
| servicemap | hosts ok/unreachable, components, AI components, changes by kind | change summary, one line per added/removed/changed component or host, host count |

Every agent also gets `mikes_agent_last_run_timestamp_seconds` and `mikes_agent_report_present`. A report is pushed to
Loki once per new report id; after a restart the latest reports are pushed again with the same timestamps and lines,
which Loki drops as duplicates.

## Grafana

Dashboard **Agent Lab · Daily Reports** (`/d/agent-daily-reports`), source copy in
[`grafana/daily-reports.json`](grafana/daily-reports.json), installed at
`/opt/monitoring/grafana/dashboards/Agent Lab/daily-reports.json`. Each report-log panel's title menu links to that
agent's full HTML report, and the **Full reports** panel and the dashboard links open the report listing
`http://192.168.1.98:9440/reports/` (served by [servicemap-web](../servicemap-agent/), LAN only).

## Files

| File | Installed at |
|---|---|
| `agenthub.py` | `/opt/agenthub/agenthub.py` |
| `agenthub.service` | `/etc/systemd/system/agenthub.service` (`AGENTHUB_PORT=9430`, `AGENTHUB_LOKI=1`, `AGENTHUB_POLL=20`) |

## Install (on .98)

```bash
sudo mkdir -p /opt/agenthub && sudo install -m 755 agenthub.py /opt/agenthub/
sudo install -m 644 agenthub.service /etc/systemd/system/ && sudo systemctl daemon-reload
sudo systemctl enable --now agenthub.service
sudo install -d -o 472 -g root "/opt/monitoring/grafana/dashboards/Agent Lab"
sudo install -m 644 grafana/daily-reports.json "/opt/monitoring/grafana/dashboards/Agent Lab/"
```

Prometheus scrape job in `/opt/monitoring/prometheus/config/prometheus.yml`, then `curl -X POST localhost:9090/-/reload`:

```yaml
  - job_name: agenthub
    static_configs:
      - targets: ["localhost:9430"]
        labels: {host: hv-rocky-linux-1, job: agenthub}
```

Loki needs nothing extra: agenthub pushes to `http://localhost:3100/loki/api/v1/push` on the same host.

Add an agent: put its report folder in `REPORT_DIRS`, add a branch to `metrics_for()` and `loki_lines()`, then
`sudo install -m 755 agenthub.py /opt/agenthub/ && sudo systemctl restart agenthub`.
