# labwatch-agent: morning lab health briefing

Part of [mikes-agents](../README.md). Uses [lab-agents-common](../lab-agents-common/).

Every day at **06:15** it checks the lab through the observability hub on .98 (Prometheus, Loki,
Alertmanager) and emails a GREEN / YELLOW / RED briefing in plain English. It's a **tool-using agent**:
after a fixed snapshot it runs its own PromQL and LogQL queries to confirm problems and read the actual log
lines before it reports.

```
            ┌────────── snapshot (14 PromQL checks + Loki error counts + Alertmanager) ──────────┐
labwatch ───┤                                                                                     │
            └─► LiteLLM ─► qwen3.8-27b ──tool calls──► prometheus_query / prometheus_range /       │
                     ▲                                  loki_logs / loki_metric  ◄── .98 :9090/:3100
                     └──────────── results (≤6000 chars each), up to 8 rounds ─────────────────────┘
                                  final JSON → HTML report → /opt/labagents/data/reports/labwatch + Gmail
```

## Snapshot checks

| Check | PromQL (simplified) |
|---|---|
| targets down | `up == 0` |
| firing alerts | `ALERTS{alertstate="firing"}` + Alertmanager `/api/v2/alerts` |
| disks > 70 % | `1 - avail/size` on real filesystems |
| disk full within 7 days | `predict_linear(node_filesystem_avail_bytes[24h], 7d) < 0` |
| memory > 85 % | `1 - MemAvailable/MemTotal` |
| load15 per CPU > 1 | `node_load15 / count(node_cpu_seconds_total{mode="idle"})` |
| rebooted in 24 h, uptime | `time() - node_boot_time_seconds` |
| failed systemd units | `node_systemd_unit_state{state="failed"} == 1` |
| CPU temp > 70 °C | `node_thermal_zone_temp` |
| podman containers not running / unhealthy | `podman_container_state != 2`, `podman_container_health == 1` |
| container restarts (cAdvisor) | `changes(container_start_time_seconds[24h]) > 0` |
| NIC receive errors | `increase(node_network_receive_errs_total[24h]) > 100` |
| top error log sources | LogQL `topk(15, sum by (host, service_name) (count_over_time({level=~"error|crit"}[24h])))` |

## Tools the model can call

| Tool | Does |
|---|---|
| `prometheus_query(promql)` | instant query, up to 40 series |
| `prometheus_range(promql, hours)` | range query, min / max / last per series |
| `loki_logs(logql, hours, limit)` | newest log lines (≤50) for a stream selector |
| `loki_metric(logql)` | LogQL metric query |

The prompt tells it the host map, that rk3/rk4 (.77/.78) are reserved and may be down on purpose, and that
errors from the vulnerable-app labs on .101/.102 are often expected demo traffic.

## Output

Report: `/opt/labagents/data/reports/labwatch/<date>.html` + `.json` (result plus the raw snapshot),
`latest.html`. Email subject: `Lab health [YELLOW]: <headline>`.

First test run (2026-10-07): 11 tool calls, 87 s, YELLOW. It found that rk2 had rebooted 18 minutes earlier
with microk8s/dqlite still starting, that rk1/rasp5 had rebooted within 24 h, and that rk3 was down as expected.

## Files

| File | Installed at |
|---|---|
| `labwatch.py` | `/opt/labagents/app/labagents/labwatch.py` (in the image) |
| `labwatch` | `/usr/local/bin/labwatch` |
| `labwatch.service` / `.timer` | `/etc/systemd/system/` (06:15 daily) |

## Install

After [lab-agents-common](../lab-agents-common/) is set up and `LABWATCH_KEY` is in the env file:

```bash
sudo cp labwatch.py /opt/labagents/app/labagents/
sudo podman build -t localhost/labagents:latest -f /opt/labagents/app/Containerfile /opt/labagents/app
sudo install -m 755 labwatch /usr/local/bin/labwatch
sudo cp labwatch.service labwatch.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now labwatch.timer
labwatch --no-email
```

## Usage

```bash
labwatch                  # run + email
labwatch --no-email       # report only
labwatch --max-tools 4    # fewer investigation rounds (faster, lighter on the GPU)
labwatch --to someone@example.com
```
