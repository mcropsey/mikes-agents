"""labwatch-agent: morning lab health briefing.

Takes a fixed health snapshot from Prometheus, Loki and Alertmanager on .98, then lets the model
investigate with its own PromQL/LogQL tool calls before writing a plain-English report.

Usage: python -m labagents.labwatch [--no-email] [--to ADDR] [--max-tools N]
"""
import argparse
import datetime as dt
import json
import os
import time

import httpx

from .common import LAB_HOSTS, MAIL_TO, Agent, card, e, log, page, save_report, send_mail, table

PROM = os.environ.get("PROM_URL", "http://192.168.1.98:9090")
LOKI = os.environ.get("LOKI_URL", "http://192.168.1.98:3100")
ALERTMANAGER = os.environ.get("ALERTMANAGER_URL", "http://192.168.1.98:9093")
http = httpx.Client(timeout=60)

REAL_FS = 'fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs|nfs.*|fuse.*"'
SNAPSHOT_QUERIES = {
    "targets_down": "up == 0",
    "alerts_firing": 'ALERTS{alertstate="firing"}',
    "disk_used_pct_over_70": f"round(100 * (1 - node_filesystem_avail_bytes{{{REAL_FS}}} / node_filesystem_size_bytes{{{REAL_FS}}})) > 70",
    "disk_full_within_7d": f"predict_linear(node_filesystem_avail_bytes{{{REAL_FS}}}[24h], 7*86400) < 0",
    "mem_used_pct_over_85": "round(100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 85",
    "load_per_cpu_over_1": 'round(node_load15 / on(instance) count by (instance) (node_cpu_seconds_total{mode="idle"}), 0.01) > 1',
    "rebooted_last_24h": "round((time() - node_boot_time_seconds) / 3600, 0.1) < 24",
    "uptime_days": "round((time() - node_boot_time_seconds) / 86400, 0.1)",
    "failed_systemd_units": 'node_systemd_unit_state{state="failed"} == 1',
    "cpu_temp_c_over_70": "max by (instance, host) (node_thermal_zone_temp) > 70",
    "podman_containers_not_running": "podman_container_state != 2",
    "podman_unhealthy": "podman_container_health == 1",
    "cadvisor_container_restarts_24h": 'changes(container_start_time_seconds{name!=""}[24h]) > 0',
    "net_rx_errors_24h": "increase(node_network_receive_errs_total[24h]) > 100",
}
LOKI_ERRORS_24H = 'topk(15, sum by (host, service_name) (count_over_time({level=~"error|crit"}[24h])))'

SYSTEM = f"""You are the on-call SRE for a home lab. Each morning you check its health and brief the owner.

Lab hosts:
{LAB_HOSTS}

You get a health snapshot (Prometheus, Loki error counts, Alertmanager). Use the tools to dig into anything
abnormal: confirm problems, find the cause, and look at actual log lines before blaming a service.
Spend at most a handful of tool calls, and don't re-query what the snapshot already shows.
Known noise: rk3 (.77) and rk4 (.78) are reserved spares and may be down on purpose: list them as "info" only.
Error log lines from the crAPI / Juice Shop / VAmPI / DVGA vulnerable-app labs on .101/.102 are often
expected attack-demo traffic.

When done, reply with ONLY this JSON:
{{"status": "green|yellow|red",
 "headline": "one sentence",
 "summary": "2-4 sentences: overall state of the lab",
 "issues": [{{"severity": "critical|high|medium|low|info", "host": "name (ip)", "title": "...",
             "details": "what you found, with numbers", "action": "concrete next step or empty"}}],
 "healthy": ["short notes on what looks fine"]}}
Order issues by severity. green = nothing needs attention, yellow = something to look at today,
red = something is broken now."""

TOOLS = [
    {"type": "function", "function": {
        "name": "prometheus_query",
        "description": "Run an instant PromQL query against the lab Prometheus. Returns up to 40 series.",
        "parameters": {"type": "object", "properties": {"promql": {"type": "string"}}, "required": ["promql"]}}},
    {"type": "function", "function": {
        "name": "prometheus_range",
        "description": "Run a PromQL range query; returns min/max/last per series over the window.",
        "parameters": {"type": "object", "properties": {
            "promql": {"type": "string"}, "hours": {"type": "number", "description": "look-back, default 24"}},
            "required": ["promql"]}}},
    {"type": "function", "function": {
        "name": "loki_logs",
        "description": "Fetch recent log lines from Loki with a LogQL stream selector, e.g. "
                       '{host="hv-rocky-linux-4", service_name="postgresdb", level="error"}. '
                       "Labels: host, service_name, container, unit, job, level, namespace, pod.",
        "parameters": {"type": "object", "properties": {
            "logql": {"type": "string"}, "hours": {"type": "number", "description": "default 24"},
            "limit": {"type": "integer", "description": "default 20, max 50"}}, "required": ["logql"]}}},
    {"type": "function", "function": {
        "name": "loki_metric",
        "description": "Run a LogQL metric query (e.g. sum by (service_name) (count_over_time({...}[24h]))).",
        "parameters": {"type": "object", "properties": {"logql": {"type": "string"}}, "required": ["logql"]}}},
]


def _labels(metric: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in metric.items() if k != "__name__")


def prometheus_query(promql: str) -> str:
    r = http.get(f"{PROM}/api/v1/query", params={"query": promql}).json()
    if r.get("status") != "success":
        return f"ERROR: {r.get('error')}"
    res = r["data"]["result"]
    lines = [f"{_labels(x['metric'])} => {x['value'][1]}" for x in res[:40]]
    return f"{len(res)} series\n" + "\n".join(lines) if res else "0 series (empty result)"


def prometheus_range(promql: str, hours: float = 24) -> str:
    end = time.time()
    step = max(60, int(hours * 3600 / 200))
    r = http.get(f"{PROM}/api/v1/query_range",
                 params={"query": promql, "start": end - hours * 3600, "end": end, "step": step}).json()
    if r.get("status") != "success":
        return f"ERROR: {r.get('error')}"
    out = []
    for x in r["data"]["result"][:30]:
        vals = [float(v[1]) for v in x["values"]]
        out.append(f"{_labels(x['metric'])} => min {min(vals):.3g} max {max(vals):.3g} last {vals[-1]:.3g}")
    return "\n".join(out) or "0 series (empty result)"


def loki_logs(logql: str, hours: float = 24, limit: int = 20) -> str:
    end = time.time_ns()
    r = http.get(f"{LOKI}/loki/api/v1/query_range", params={
        "query": logql, "start": end - int(hours * 3600e9), "end": end, "limit": min(int(limit), 50),
        "direction": "backward"}).json()
    if r.get("status") != "success":
        return f"ERROR: {r}"[:500]
    lines = []
    for stream in r["data"]["result"]:
        lab = stream["stream"]
        tag = f"{lab.get('host', '?')}/{lab.get('service_name') or lab.get('unit') or lab.get('container', '?')}"
        for ts, line in stream["values"]:
            lines.append((int(ts), f"{dt.datetime.fromtimestamp(int(ts) / 1e9):%m-%d %H:%M:%S} {tag}: {line[:300]}"))
    return "\n".join(l for _, l in sorted(lines, reverse=True)) or "no log lines"


def loki_metric(logql: str) -> str:
    r = http.get(f"{LOKI}/loki/api/v1/query", params={"query": logql}).json()
    if r.get("status") != "success":
        return f"ERROR: {r}"[:500]
    res = r["data"]["result"]
    return "\n".join(f"{_labels(x['metric'])} => {x['value'][1]}" for x in res[:40]) or "0 series"


def alertmanager_alerts() -> list:
    alerts = http.get(f"{ALERTMANAGER}/api/v2/alerts", params={"active": "true"}).json()
    return [{"alert": a["labels"].get("alertname"), "instance": a["labels"].get("instance", a["labels"].get("host")),
             "severity": a["labels"].get("severity"), "since": a["startsAt"][:16],
             "summary": a.get("annotations", {}).get("summary"), "silenced": bool(a["status"].get("silencedBy"))}
            for a in alerts]


def snapshot() -> dict:
    snap = {"taken_at": dt.datetime.now().isoformat(timespec="minutes")}
    for name, q in SNAPSHOT_QUERIES.items():
        try:
            snap[name] = prometheus_query(q)
        except Exception as ex:
            snap[name] = f"ERROR {ex}"
    try:
        snap["loki_error_lines_24h_top15"] = loki_metric(LOKI_ERRORS_24H)
    except Exception as ex:
        snap["loki_error_lines_24h_top15"] = f"ERROR {ex}"
    try:
        snap["alertmanager_active"] = alertmanager_alerts()
    except Exception as ex:
        snap["alertmanager_active"] = f"ERROR {ex}"
    return snap


def render(result: dict, snap: dict, footer: str) -> str:
    status = str(result.get("status", "yellow")).lower()
    color = {"green": "#2f855a", "yellow": "#b08800", "red": "#b42318"}.get(status, "#4a5568")
    issues = "".join(card(i.get("severity", "info"), i.get("title", ""),
                          f'<div>{e(i.get("details"))}</div>'
                          + (f'<div style="margin-top:4px"><b>Action:</b> {e(i["action"])}</div>' if i.get("action") else ""),
                          i.get("host", "")) for i in result.get("issues", []))
    healthy = "".join(f"<li>{e(h)}</li>" for h in result.get("healthy", []))
    alerts = snap.get("alertmanager_active")
    alert_rows = table(["Alert", "Instance", "Since", "Summary"],
                       [[e(a["alert"]), e(a["instance"]), e(a["since"]), e(a["summary"])] for a in alerts]) \
        if isinstance(alerts, list) and alerts else "<p>No active alerts.</p>"
    return page(f"Lab health: {dt.datetime.now():%a %b %d}",
                f'<p style="font-size:16px"><span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-weight:600">{e(status.upper())}</span> <b>{e(result.get("headline"))}</b></p>'
                f'<p>{e(result.get("summary"))}</p>{issues}'
                + (f"<h3>Looks healthy</h3><ul>{healthy}</ul>" if healthy else "")
                + f"<h3>Active alerts (Alertmanager)</h3>{alert_rows}"
                + '<p style="font-size:12px">Grafana: <a href="http://192.168.1.98:3000">http://192.168.1.98:3000</a></p>',
                footer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to")
    ap.add_argument("--max-tools", type=int, default=8, help="max tool-calling rounds (default 8)")
    args = ap.parse_args()

    agent = Agent("labwatch-agent")
    snap = snapshot()
    log(f"snapshot taken: {sum(1 for k in SNAPSHOT_QUERIES if not str(snap[k]).startswith('0 series'))} "
        f"non-empty checks, {len(snap['alertmanager_active']) if isinstance(snap['alertmanager_active'], list) else '?'} alerts")
    result = agent.run_tools(SYSTEM, "Health snapshot:\n" + json.dumps(snap, indent=1),
                             TOOLS, {"prometheus_query": prometheus_query, "prometheus_range": prometheus_range,
                                     "loki_logs": loki_logs, "loki_metric": loki_metric},
                             max_rounds=args.max_tools)
    log(f"status {result.get('status')}: {len(result.get('issues', []))} issues")
    body = render(result, snap, agent.footer())
    save_report("labwatch", body, {"result": result, "snapshot": snap})
    if not args.no_email:
        send_mail(f"Lab health [{str(result.get('status', '?')).upper()}]: {result.get('headline', '')[:90]}",
                  body, args.to or MAIL_TO)


if __name__ == "__main__":
    main()
