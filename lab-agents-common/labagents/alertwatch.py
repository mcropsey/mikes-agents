"""alertwatch-agent: on-demand triage of Alertmanager alerts.

Unlike the morning agents, this one is *event-driven*: Alertmanager POSTs firing alerts to the receiver
(`--serve`, :9435) and the agent investigates each group with the same Prometheus/Loki tools labwatch uses,
then emails a short "what fired, likely cause, what to do" note. It is deliberately bounded so it never
hammers the interactive GPU:

  * alerts that arrive close together are coalesced into one triage,
  * at most one LLM triage runs per MIN_INTERVAL (default 10 min),
  * between 08:00 and 22:00 (GPU used interactively) only `critical` alerts are triaged live; everything
    else is held and flushed in one batch at the top of the next hour.

`--test` triages whatever is firing right now, once (manual use / demo / fallback timer).

Usage:
  python -m labagents.alertwatch --serve                 # always-on receiver (alertwatch.service)
  python -m labagents.alertwatch --test [--no-email]     # triage current firing alerts once
"""
import argparse
import datetime as dt
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .common import LAB_HOSTS, MAIL_TO, Agent, card, e, log, page, save_report, send_mail, table
from .labwatch import (ALERTMANAGER, TOOLS, alertmanager_alerts, loki_logs, loki_metric,
                       prometheus_query, prometheus_range)

PORT = int(os.environ.get("ALERTWATCH_PORT", "9435"))
MIN_INTERVAL = int(os.environ.get("ALERTWATCH_MIN_INTERVAL", "600"))   # seconds between LLM triages
COALESCE = int(os.environ.get("ALERTWATCH_COALESCE", "60"))            # wait this long to batch arrivals
QUIET_START, QUIET_END = 8, 22                                        # live-triage only criticals in this window
HANDLERS = {"prometheus_query": prometheus_query, "prometheus_range": prometheus_range,
            "loki_logs": loki_logs, "loki_metric": loki_metric}

SYSTEM = f"""You are the on-call SRE for a home lab. An alert just fired. Triage it for the owner: say what
it means, confirm whether it is really a problem right now, find the likely cause from metrics and logs, and
give one concrete next step. Be quick and specific; a handful of tool calls at most.

Lab hosts:
{LAB_HOSTS}

Known noise: rk3 (.77) and rk4 (.78) are reserved spares and may be down on purpose (treat as info). Error
log lines from the crAPI / Juice Shop / VAmPI / DVGA vulnerable-app labs on .101/.102 are often expected
attack-demo traffic. The lab's own agents (labwatch/cvewatch/patchwatch/secnews/servicemap) run 05:30-07:00.

Reply with ONLY this JSON:
{{"status": "red|yellow|green",
 "headline": "one sentence naming the alert(s) and the verdict",
 "summary": "2-4 sentences: what fired and whether it matters now",
 "alerts": [{{"alertname": "...", "host": "name (ip)", "severity": "critical|high|medium|low|info",
              "real": true, "cause": "what you found, with numbers", "action": "concrete next step"}}]}}
status red = acting now, yellow = look today, green = self-resolved or false alarm."""


def _fmt_alerts(alerts: list) -> str:
    rows = []
    for a in alerts:
        lab = a.get("labels", a)
        rows.append({"alertname": lab.get("alertname"), "severity": lab.get("severity"),
                     "instance": lab.get("instance") or lab.get("host"), "host": lab.get("host"),
                     "startsAt": (a.get("startsAt") or "")[:16],
                     "summary": (a.get("annotations", {}) or {}).get("summary"),
                     "description": (a.get("annotations", {}) or {}).get("description")})
    return json.dumps(rows, indent=1)


def triage(agent: Agent, alerts: list, max_tools: int = 6) -> dict:
    user = ("These alerts are firing. Triage them:\n" + _fmt_alerts(alerts)
            + "\n\nFor context, everything currently active in Alertmanager:\n"
            + json.dumps(alertmanager_alerts(), indent=1))
    return agent.run_tools(SYSTEM, user, TOOLS, HANDLERS, max_rounds=max_tools)


def render(result: dict, footer: str) -> str:
    status = str(result.get("status", "yellow")).lower()
    color = {"green": "#2f855a", "yellow": "#b08800", "red": "#b42318"}.get(status, "#4a5568")
    cards = "".join(card(a.get("severity", "info"), a.get("alertname", ""),
                         f'<div>{e(a.get("cause"))}</div>'
                         + (f'<div style="margin-top:4px"><b>Action:</b> {e(a["action"])}</div>' if a.get("action") else "")
                         + ("" if a.get("real", True) else '<div style="color:#2f855a">Assessed as a false alarm / already resolved.</div>'),
                         a.get("host", "")) for a in result.get("alerts", []))
    return page(f"Alert triage: {dt.datetime.now():%a %b %d %H:%M}",
                f'<p style="font-size:16px"><span style="background:{color};color:#fff;padding:2px 8px;'
                f'border-radius:4px;font-weight:600">{e(status.upper())}</span> <b>{e(result.get("headline"))}</b></p>'
                f'<p>{e(result.get("summary"))}</p>{cards}'
                '<p style="font-size:12px">Grafana: <a href="http://192.168.1.98:3000/d/agent-daily-reports">'
                'Daily Reports</a> · <a href="http://192.168.1.98:9093">Alertmanager</a></p>',
                footer)


def run_once(alerts: list, email: bool = True, to: str = MAIL_TO) -> dict:
    if not alerts:
        log("no firing alerts to triage")
        return {}
    agent = Agent("alertwatch-agent")
    names = ", ".join(sorted({(a.get("labels", a)).get("alertname", "?") for a in alerts}))
    log(f"triaging {len(alerts)} alert(s): {names}")
    result = triage(agent, alerts)
    body = render(result, agent.footer())
    save_report("alertwatch", body, {"result": result, "alerts": [a.get("labels", a) for a in alerts]})
    if email:
        send_mail(f"Alert triage [{str(result.get('status', '?')).upper()}]: {result.get('headline', '')[:80]}",
                  body, to)
    return result


# ---------- event-driven receiver ----------

class _Queue:
    """Pending alerts + cooldown. A critical alert bypasses the quiet-hours hold."""

    def __init__(self):
        self.pending: dict[str, dict] = {}        # fingerprint -> alert
        self.last_run = 0.0
        self.last_arrival = 0.0
        self.lock = threading.Lock()

    def add(self, alerts: list):
        with self.lock:
            for a in alerts:
                if a.get("status") == "resolved":
                    continue
                fp = a.get("fingerprint") or json.dumps(a.get("labels", {}), sort_keys=True)
                self.pending[fp] = a
            self.last_arrival = time.monotonic()

    def due(self) -> list:
        with self.lock:
            if not self.pending:
                return []
            now = time.monotonic()
            if now - self.last_arrival < COALESCE:            # still batching recent arrivals
                return []
            if now - self.last_run < MIN_INTERVAL:            # cooldown between LLM triages
                return []
            crit = any((a.get("labels", {}) or {}).get("severity") == "critical" for a in self.pending.values())
            hour = dt.datetime.now().hour
            quiet = QUIET_START <= hour < QUIET_END
            if quiet and not crit and dt.datetime.now().minute >= 2:
                # Hold non-critical alerts through the interactive day; flush only at the top of the hour.
                return []
            batch = list(self.pending.values())
            self.pending.clear()
            self.last_run = now
            return batch


def serve():
    q = _Queue()

    def worker():
        while True:
            try:
                batch = q.due()
                if batch:
                    run_once(batch, email=True)
            except Exception as ex:
                log(f"triage worker error: {ex}")
            time.sleep(10)

    class H(BaseHTTPRequestHandler):
        def _send(self, code, text="ok\n"):
            b = text.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._send(200, "alertwatch receiver ok\n") if self.path in ("/", "/healthz") else self._send(404, "no\n")

        def do_POST(self):
            if self.path not in ("/alert", "/alert/"):
                return self._send(404, "no\n")
            try:
                n = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(n) or b"{}")
                alerts = payload.get("alerts", payload if isinstance(payload, list) else [])
                q.add(alerts)
                log(f"received {len(alerts)} alert(s) from Alertmanager")
                self._send(200)
            except Exception as ex:
                log(f"bad webhook: {ex}")
                self._send(400, "bad\n")

        def log_message(self, *a):
            pass

    threading.Thread(target=worker, daemon=True).start()
    log(f"alertwatch receiver on :{PORT} (min_interval={MIN_INTERVAL}s, coalesce={COALESCE}s, "
        f"quiet {QUIET_START:02d}-{QUIET_END:02d} criticals-only)")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true", help="run the always-on Alertmanager webhook receiver")
    ap.add_argument("--test", action="store_true", help="triage currently firing alerts once and exit")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to")
    args = ap.parse_args()
    if args.serve:
        return serve()
    # --test / default: pull what Alertmanager has firing right now.
    import httpx
    active = httpx.get(f"{ALERTMANAGER}/api/v2/alerts", params={"active": "true"}, timeout=30).json()
    firing = [a for a in active if a.get("status", {}).get("state") == "active"]
    if not firing:
        log("nothing firing; writing a GREEN report")
        agent = Agent("alertwatch-agent")
        res = {"status": "green", "headline": "No alerts firing", "summary": "Alertmanager has no active alerts.",
               "alerts": []}
        body = render(res, agent.footer("no LLM call"))
        save_report("alertwatch", body, {"result": res, "alerts": []})
        if not args.no_email:
            send_mail("Alert triage [GREEN]: no alerts firing", body, args.to or MAIL_TO)
        return
    run_once(firing, email=not args.no_email, to=args.to or MAIL_TO)


if __name__ == "__main__":
    main()
