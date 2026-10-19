# alertwatch-agent

Part of [mikes-agents](../README.md). **Event-driven** triage of Alertmanager alerts. When an alert fires,
Alertmanager POSTs it to alertwatch's receiver; alertwatch investigates with the same Prometheus/Loki tools
[labwatch](../labwatch-agent/) uses, decides whether it is really a problem, and emails a short
"what fired · likely cause · next step" note.

Unlike the morning agents it can run any time, so it is deliberately bounded to protect the interactive GPU:

- arrivals within `ALERTWATCH_COALESCE` (default 60s) are batched into one triage,
- at most one LLM triage per `ALERTWATCH_MIN_INTERVAL` (default 600s),
- between 08:00 and 22:00 only **critical** alerts are triaged live; everything else is held and flushed in one
  batch at the top of the next hour.

## Run

| Mode | Command |
|---|---|
| Always-on receiver (`:9435`) | `alertwatch.service` → `labagents.alertwatch --serve` |
| Daily heartbeat 07:00 | `alertwatch.timer` → `alertwatch-heartbeat.service` → `--test` |
| Manual: triage what's firing now | `alertwatch` (wrapper; `--no-email` to skip mail) |

When nothing is firing, `--test` writes a GREEN report with **no LLM call** (cheap heartbeat).

## Wiring

Alertmanager (`/opt/monitoring/alertmanager/config/alertmanager.yml`) sends to the webhook receiver:

```yaml
route:
  receiver: "alertwatch"
receivers:
  - name: "alertwatch"
    webhook_configs:
      - url: http://192.168.1.98:9435/alert
        send_resolved: false
```

Restart Alertmanager after editing (lifecycle reload isn't enabled on v0.34.1). Previous `null`-receiver config
is backed up next to the live file (`alertmanager.yml.bak-pre-alertwatch-20261019`).

## LiteLLM

Key `ALERTWATCH_KEY`, alias `alertwatch-agent`, opted out of `basic-safety-filter` (it reasons about attacks).
See [litellm/](../litellm/).

## Config (env file)

`ALERTWATCH_PORT` (9435), `ALERTWATCH_MIN_INTERVAL` (600s), `ALERTWATCH_COALESCE` (60s); plus the shared
`PROM_URL` / `LOKI_URL` / `ALERTMANAGER_URL`.

## Reports & Grafana

`/opt/labagents/data/reports/alertwatch/`, listed at `:9440/reports/#alertwatch`, metrics
(`mikes_alertwatch_*`) and report logs via [agenthub](../agenthub/) on dashboards *Agent Lab · Daily Reports*
and *Agent Lab · Agents II*.

## Test the receiver

```bash
curl -X POST localhost:9435/alert -H 'Content-Type: application/json' \
  -d '{"alerts":[{"status":"firing","labels":{"alertname":"SelfTest","severity":"info","host":"hv-rocky-linux-1"},"annotations":{"summary":"ignore"}}]}'
# then restart alertwatch to drop the test alert from the in-memory queue
sudo systemctl restart alertwatch
```
