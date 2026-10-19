#!/usr/bin/env python3
import json
import os
import re
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPORT_DIRS = {
    "labwatch": "/opt/labagents/data/reports/labwatch",
    "cvewatch": "/opt/labagents/data/reports/cvewatch",
    "patchwatch": "/opt/labagents/data/reports/patchwatch",
    "secnews": "/opt/secnews/data/reports",
    "servicemap": "/opt/labagents/data/reports/servicemap",
    # added 2026-10-19
    "alertwatch": "/opt/labagents/data/reports/alertwatch",
    "weekrollup": "/opt/labagents/data/reports/weekrollup",
    "patchrun": "/opt/labagents/data/reports/patchrun",
    "agentdemo": "/opt/labagents/data/reports/agentdemo",
    "llmredteam": "/opt/labagents/data/reports/llmredteam",
}
PORT = int(os.environ.get("AGENTHUB_PORT", "9430"))
LOKI_URL = os.environ.get("AGENTHUB_LOKI_URL", "http://localhost:3100/loki/api/v1/push")
LOKI_ON = os.environ.get("AGENTHUB_LOKI", "1") not in ("0", "false", "no")
POLL = int(os.environ.get("AGENTHUB_POLL", "20"))
REPORT_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}_\d{4})\.json$")

HELP = {
    "mikes_agent_report_present": "1 when the exporter has a latest report for this agent",
    "mikes_agent_last_run_timestamp_seconds": "Unix time the latest report was written",
    "mikes_agent_status_code": "labwatch status: 0 green, 1 yellow, 2 red, 3 unknown",
    "mikes_agent_status": "labwatch status label, value 1",
    "mikes_agent_issue_count": "labwatch issue count by severity (severity=total for all)",
    "mikes_agent_healthy_count": "labwatch checks that passed",
    "mikes_cvewatch_finding_count": "cvewatch findings by verdict (verdict=total for all)",
    "mikes_cvewatch_affected_severity": "cvewatch affected findings by severity",
    "mikes_cvewatch_cves_matched": "cvewatch: CVEs matched against the inventory",
    "mikes_patchwatch_priority_count": "patchwatch patch items by priority (priority=total for all)",
    "mikes_patchwatch_hosts": "patchwatch: hosts in scope",
    "mikes_patchwatch_hosts_with_updates": "patchwatch: hosts with pending updates",
    "mikes_patchwatch_advisories": "patchwatch: security advisories seen",
    "mikes_patchwatch_critical_advisories": "patchwatch: Critical advisories",
    "mikes_secnews_story_count": "secnews: stories in the digest",
    "mikes_secnews_story_severity": "secnews: stories by severity",
    "mikes_secnews_kev_present": "1 when the digest carries CISA KEV notes",
    "mikes_servicemap_hosts": "servicemap: hosts mapped (state=ok|unreachable)",
    "mikes_servicemap_components": "servicemap: notable components (excl. OS baseline)",
    "mikes_servicemap_ai_components": "servicemap: components that use or serve an LLM",
    "mikes_servicemap_changes": "servicemap: changes since the previous map by kind (kind=total for all)",
    "mikes_alertwatch_status_code": "alertwatch triage status: 0 green, 1 yellow, 2 red, 3 unknown",
    "mikes_alertwatch_alert_count": "alertwatch: alerts in the latest triage (kind=total|real|false)",
    "mikes_weekrollup_open_items": "weekrollup: items still open / recurring this week",
    "mikes_weekrollup_quality_issues": "weekrollup: agent quality-check notes by severity (severity=total for all)",
    "mikes_patchrun_status_code": "patchrun status: 0 ok, 1 attention, 2 failed, 3 unknown",
    "mikes_patchrun_hosts": "patchrun: hosts in the run by result (result=patched|dry-run|failed|total)",
    "mikes_patchrun_reboots_needed": "patchrun: hosts needing a reboot after the run",
    "mikes_patchrun_applied": "patchrun: 1 if updates were actually applied, 0 for a dry-run",
    "mikes_agentdemo_calls": "agentdemo: MCP tool calls in the latest run by persona",
    "mikes_agentdemo_sensitive": "agentdemo: cross-account/bulk calls by persona (the hijack signature)",
    "mikes_llmredteam_probes": "llmredteam: probes sent in the latest eval",
    "mikes_llmredteam_outcome": "llmredteam: probes by outcome (outcome=blocked|refused|complied|partial|error)",
    "mikes_llmredteam_findings": "llmredteam: probes the model complied with (findings)",
    "mikes_llmredteam_status_code": "llmredteam status: 0 green, 1 yellow, 2 red, 3 unknown",
}
TYPE = {n: "gauge" for n in HELP}

_PUSHED = {}
_LOCK = threading.Lock()


def latest(agent):
    d = REPORT_DIRS[agent]
    try:
        names = [f for f in os.listdir(d) if REPORT_RE.match(f)]
    except OSError:
        return None
    if not names:
        return None
    names.sort()
    name = names[-1]
    m = REPORT_RE.match(name)
    path = os.path.join(d, name)
    try:
        with open(path) as fh:
            data = json.load(fh)
    except Exception:
        return None
    return {"agent": agent, "id": m.group(1), "file": name, "path": path,
            "ts": os.path.getmtime(path), "data": data}


def num(v):
    try:
        return float(v)
    except Exception:
        return 0.0


def count(items, pred):
    n = 0
    for x in items or []:
        if isinstance(x, dict) and pred(x):
            n += 1
    return n


def metrics_for(rep):
    agent = rep["agent"]
    data = rep["data"] if isinstance(rep["data"], dict) else {}
    res = data.get("result")
    if not isinstance(res, dict):
        res = data
    out = []
    if agent == "labwatch":
        status = str(res.get("status", "unknown")).lower()
        code = {"green": 0, "yellow": 1, "red": 2}.get(status, 3)
        out.append(("mikes_agent_status_code", {"agent": agent}, code))
        out.append(("mikes_agent_status", {"agent": agent, "status": status}, 1))
        issues = res.get("issues") or []
        out.append(("mikes_agent_issue_count", {"agent": agent, "severity": "total"}, len(issues)))
        for sev in ("info", "warning", "critical"):
            n = count(issues, lambda i, s=sev: str(i.get("severity", "")).lower() == s)
            if n:
                out.append(("mikes_agent_issue_count", {"agent": agent, "severity": sev}, n))
        out.append(("mikes_agent_healthy_count", {"agent": agent}, len(res.get("healthy") or [])))
    elif agent == "cvewatch":
        findings = res.get("findings") or []
        out.append(("mikes_cvewatch_finding_count", {"agent": agent, "verdict": "total"}, len(findings)))
        for v in ("affected", "possibly_affected", "not_affected"):
            n = count(findings, lambda f, vv=v: f.get("verdict") == vv)
            if n:
                out.append(("mikes_cvewatch_finding_count", {"agent": agent, "verdict": v}, n))
        for sev in ("critical", "high", "medium", "low"):
            n = count(findings, lambda f, s=sev: f.get("verdict") == "affected" and f.get("severity") == s)
            if n:
                out.append(("mikes_cvewatch_affected_severity", {"agent": agent, "severity": sev}, n))
        stats = data.get("stats") or {}
        out.append(("mikes_cvewatch_cves_matched", {"agent": agent}, num(stats.get("cves_matched", 0))))
    elif agent == "patchwatch":
        prios = res.get("priorities") or []
        out.append(("mikes_patchwatch_priority_count", {"agent": agent, "priority": "total"}, len(prios)))
        for p in ("critical", "important", "moderate", "low"):
            n = count(prios, lambda x, pp=p: str(x.get("priority", "")).lower() == pp)
            if n:
                out.append(("mikes_patchwatch_priority_count", {"agent": agent, "priority": p}, n))
        hosts = data.get("hosts") or []
        out.append(("mikes_patchwatch_hosts", {"agent": agent}, len(hosts)))
        out.append(("mikes_patchwatch_hosts_with_updates", {"agent": agent},
                    count(hosts, lambda h: num(h.get("pending_updates", 0)) > 0)))
        adv = data.get("advisories") or []
        out.append(("mikes_patchwatch_advisories", {"agent": agent}, len(adv)))
        out.append(("mikes_patchwatch_critical_advisories", {"agent": agent},
                    count(adv, lambda a: str(a.get("severity", "")).lower() == "critical")))
    elif agent == "secnews":
        stories = data.get("stories") or []
        out.append(("mikes_secnews_story_count", {"agent": agent}, len(stories)))
        for sev in ("critical", "high", "medium", "low"):
            n = count(stories, lambda s, ss=sev: str(s.get("severity", "")).lower() == ss)
            if n:
                out.append(("mikes_secnews_story_severity", {"agent": agent, "severity": sev}, n))
        out.append(("mikes_secnews_kev_present", {"agent": agent},
                    1 if str(data.get("kev_notes", "")).strip() else 0))
    elif agent == "servicemap":
        hosts = data.get("hosts") or {}
        comps = [c for c in (data.get("components") or {}).values()
                 if isinstance(c, dict) and not c.get("baseline") and c.get("kind") != "external"]
        bad = count(hosts.values(), lambda h: bool(h.get("error")))
        out.append(("mikes_servicemap_hosts", {"agent": agent, "state": "ok"}, len(hosts) - bad))
        out.append(("mikes_servicemap_hosts", {"agent": agent, "state": "unreachable"}, bad))
        out.append(("mikes_servicemap_components", {"agent": agent}, len(comps)))
        out.append(("mikes_servicemap_ai_components", {"agent": agent}, count(comps, lambda c: c.get("ai"))))
        ch = data.get("changes") or {}
        kinds = {k: len(ch.get(k) or []) for k in ("added", "removed", "changed", "hosts")}
        out.append(("mikes_servicemap_changes", {"agent": agent, "kind": "total"}, sum(kinds.values())))
        for k, n in kinds.items():
            out.append(("mikes_servicemap_changes", {"agent": agent, "kind": k}, n))
    elif agent == "alertwatch":
        status = str(res.get("status", "unknown")).lower()
        out.append(("mikes_alertwatch_status_code", {"agent": agent},
                    {"green": 0, "yellow": 1, "red": 2}.get(status, 3)))
        alerts = res.get("alerts") or []
        out.append(("mikes_alertwatch_alert_count", {"agent": agent, "kind": "total"}, len(alerts)))
        out.append(("mikes_alertwatch_alert_count", {"agent": agent, "kind": "real"},
                    count(alerts, lambda a: a.get("real", True))))
        out.append(("mikes_alertwatch_alert_count", {"agent": agent, "kind": "false"},
                    count(alerts, lambda a: not a.get("real", True))))
    elif agent == "weekrollup":
        out.append(("mikes_weekrollup_open_items", {"agent": agent}, len(res.get("open_items") or [])))
        quality = res.get("quality") or []
        out.append(("mikes_weekrollup_quality_issues", {"agent": agent, "severity": "total"}, len(quality)))
        for sev in ("high", "medium", "low"):
            n = count(quality, lambda q, s=sev: str(q.get("severity", "")).lower() == s)
            if n:
                out.append(("mikes_weekrollup_quality_issues", {"agent": agent, "severity": sev}, n))
    elif agent == "patchrun":
        status = str(res.get("status", "unknown")).lower()
        out.append(("mikes_patchrun_status_code", {"agent": agent},
                    {"ok": 0, "attention": 1, "failed": 2}.get(status, 3)))
        runs = data.get("runs") or []
        out.append(("mikes_patchrun_hosts", {"agent": agent, "result": "total"}, len(runs)))
        for r in ("patched", "failed"):
            n = count(runs, lambda x, rr=r: str(x.get("result", "")).lower() == rr)
            if n:
                out.append(("mikes_patchrun_hosts", {"agent": agent, "result": r}, n))
        out.append(("mikes_patchrun_hosts", {"agent": agent, "result": "dry-run"},
                    count(runs, lambda x: str(x.get("result", "")).startswith("dry-run"))))
        out.append(("mikes_patchrun_reboots_needed", {"agent": agent}, count(runs, lambda x: x.get("reboot"))))
        out.append(("mikes_patchrun_applied", {"agent": agent}, 1 if data.get("apply") else 0))
    elif agent == "agentdemo":
        for persona in ("baseline", "hijacked"):
            trace = data.get(persona) or []
            out.append(("mikes_agentdemo_calls", {"agent": agent, "persona": persona}, len(trace)))
            out.append(("mikes_agentdemo_sensitive", {"agent": agent, "persona": persona},
                        count(trace, lambda t: t.get("sensitive"))))
    elif agent == "llmredteam":
        rows = data.get("rows") or []
        out.append(("mikes_llmredteam_probes", {"agent": agent}, len(rows)))

        def bucket(r):  # exactly one outcome per probe
            if r.get("outcome") == "blocked":
                return "blocked"
            if r.get("outcome") == "error" or r.get("verdict") == "error":
                return "error"
            return r.get("verdict") or "error"
        for oc in ("blocked", "refused", "complied", "partial", "error"):
            n = count(rows, lambda r, o=oc: bucket(r) == o)
            if n:
                out.append(("mikes_llmredteam_outcome", {"agent": agent, "outcome": oc}, n))
        out.append(("mikes_llmredteam_findings", {"agent": agent},
                    count(rows, lambda r: r.get("verdict") in ("complied", "partial"))))
        status = str(res.get("status", "unknown")).lower()
        out.append(("mikes_llmredteam_status_code", {"agent": agent},
                    {"green": 0, "yellow": 1, "red": 2}.get(status, 3)))
    out.append(("mikes_agent_last_run_timestamp_seconds", {"agent": agent}, rep["ts"]))
    out.append(("mikes_agent_report_present", {"agent": agent}, 1))
    return out


def render_metrics():
    body = []
    seen = []
    for agent in REPORT_DIRS:
        rep = latest(agent)
        if rep is None:
            body.append('mikes_agent_report_present{agent="%s"} 0' % agent)
            continue
        for name, labels, value in metrics_for(rep):
            lab = ",".join('%s="%s"' % (k, v) for k, v in labels.items())
            body.append("%s{%s} %s" % (name, lab, value))
            if name not in seen:
                seen.append(name)
    head = []
    for name in seen:
        head.append("# HELP %s %s" % (name, HELP.get(name, "")))
        head.append("# TYPE %s %s" % (name, TYPE.get(name, "gauge")))
    return "\n".join(head + body) + "\n"


def loki_lines(agent, data):
    L = []
    res = data.get("result")
    if not isinstance(res, dict):
        res = data
    if agent == "labwatch":
        L.append("status=%s | %s" % (res.get("status", "?"), res.get("headline", "")))
        L.append("summary: %s" % res.get("summary", ""))
        for i in res.get("issues") or []:
            L.append("[%s] %s - %s: %s -> %s" % (
                i.get("severity", "?"), i.get("host", ""), i.get("title", ""),
                i.get("details", ""), i.get("action", "")))
    elif agent == "cvewatch":
        L.append("summary: %s" % res.get("summary", ""))
        for f in res.get("findings") or []:
            L.append("[%s/%s] %s: %s | %s -> %s" % (
                f.get("verdict", "?"), f.get("severity", "?"), f.get("product", ""),
                ", ".join(f.get("cves") or []), f.get("why", ""), f.get("action", "")))
        stats = data.get("stats") or {}
        L.append("stats: cves_matched=%s groups_dropped=%s" % (
            stats.get("cves_matched", "?"), stats.get("groups_dropped", "?")))
    elif agent == "patchwatch":
        L.append("headline: %s" % res.get("headline", ""))
        L.append("summary: %s" % res.get("summary", ""))
        for p in res.get("priorities") or []:
            L.append("[%s] %s (%s): %s" % (
                p.get("priority", "?"), p.get("title", ""),
                ", ".join(p.get("hosts") or []), p.get("why", "")))
    elif agent == "secnews":
        L.append("headline: %s" % data.get("headline", ""))
        L.append("summary: %s" % data.get("summary", ""))
        for s in data.get("stories") or []:
            L.append("[%s] %s: %s" % (s.get("severity", "?"), s.get("title", ""), s.get("summary", "")))
        kev = str(data.get("kev_notes", "")).strip()
        if kev:
            L.append("kev: %s" % kev)
    elif agent == "servicemap":
        hosts = data.get("hosts") or {}
        name = lambda ip: (hosts.get(ip) or {}).get("name", ip)
        ch = data.get("changes") or {}
        L.append("changes: %s" % data.get("change_summary", ""))
        for c in ch.get("added") or []:
            L.append("[added] %s (%s on %s, %s)" % (c.get("name"), c.get("kind"), name(c.get("host", "")), c.get("category", "")))
        for c in ch.get("removed") or []:
            L.append("[removed] %s (%s on %s)" % (c.get("name"), c.get("kind"), name(c.get("host", ""))))
        for c in ch.get("changed") or []:
            L.append("[changed] %s on %s: %s %s -> %s" % (c.get("name"), name(c.get("host", "")), c.get("field"),
                                                         c.get("old"), c.get("new")))
        for h in ch.get("hosts") or []:
            L.append("[host] %s: %s" % (h.get("name"), h.get("error") or "kernel %s" % " -> ".join(map(str, h.get("kernel") or []))))
        bad = [h.get("name") for h in hosts.values() if h.get("error")]
        L.append("hosts: %d mapped%s" % (len(hosts) - len(bad), ", unreachable: " + ", ".join(bad) if bad else ""))
    elif agent == "alertwatch":
        L.append("status=%s | %s" % (res.get("status", "?"), res.get("headline", "")))
        L.append("summary: %s" % res.get("summary", ""))
        for a in res.get("alerts") or []:
            L.append("[%s/%s] %s on %s: %s -> %s" % (
                a.get("severity", "?"), "real" if a.get("real", True) else "false", a.get("alertname", ""),
                a.get("host", ""), a.get("cause", ""), a.get("action", "")))
    elif agent == "weekrollup":
        L.append("headline: %s" % res.get("headline", ""))
        L.append("summary: %s" % res.get("summary", ""))
        for t in res.get("themes") or []:
            L.append("[%s] %s: %s" % (t.get("area", "?"), t.get("title", ""), t.get("detail", "")))
        for o in res.get("open_items") or []:
            L.append("[open] %s: %s -> %s" % (o.get("title", ""), o.get("detail", ""), o.get("action", "")))
        for q in res.get("quality") or []:
            L.append("[quality/%s] %s: %s (%s)" % (q.get("severity", "?"), q.get("agent", ""),
                                                   q.get("issue", ""), q.get("evidence", "")))
    elif agent == "patchrun":
        L.append("status=%s | %s" % (res.get("status", "?"), res.get("headline", "")))
        L.append("summary: %s" % res.get("summary", ""))
        for h in res.get("hosts") or []:
            L.append("[%s] %s%s: %s" % (h.get("result", "?"), h.get("host", ""),
                                        " REBOOT" if h.get("reboot_needed") else "", h.get("note", "")))
        for f in res.get("followups") or []:
            L.append("followup: %s" % f)
    elif agent == "agentdemo":
        L.append("mode=%s baseline=%d calls (%d cross-account) hijacked=%d calls (%d cross-account)" % (
            data.get("mode", "?"), len(data.get("baseline") or []), data.get("sensitive_baseline", 0),
            len(data.get("hijacked") or []), data.get("sensitive_hijacked", 0)))
        for persona in ("baseline", "hijacked"):
            for t in data.get(persona) or []:
                L.append("[%s] %s%s" % (persona, t.get("tool", ""), " (cross-account)" if t.get("sensitive") else ""))
    elif agent == "llmredteam":
        r = res if isinstance(res, dict) else {}
        L.append("status=%s findings=%s blocked=%s refused=%s of %s probes" % (
            r.get("status", "?"), r.get("findings", "?"), r.get("blocked", "?"),
            r.get("refused", "?"), r.get("total", "?")))
        for row in data.get("rows") or []:
            L.append("[%s] %s: outcome=%s verdict=%s risk=%s - %s" % (
                row.get("category", "?"), (row.get("probe", "") or "")[:60], row.get("outcome", ""),
                row.get("verdict", ""), row.get("risk", ""), row.get("why", "")))
    return L


def push_loki(rep):
    if not LOKI_ON:
        return
    agent = rep["agent"]
    data = rep["data"] if isinstance(rep["data"], dict) else {}
    res = data.get("result")
    if not isinstance(res, dict):
        res = data
    stream = {"agent": agent, "report": rep["id"]}
    if agent in ("labwatch", "alertwatch", "patchrun", "llmredteam"):
        st = str(res.get("status", "")).lower()
        if st:
            stream["status"] = st
    ns = str(int(rep["ts"] * 1e9))
    values = [[ns, line] for line in loki_lines(agent, data)]
    if not values:
        values = [[ns, "(empty report)"]]
    payload = json.dumps({"streams": [{"stream": stream, "values": values}]}).encode()
    req = urllib.request.Request(
        LOKI_URL, data=payload, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            if r.getcode() not in (200, 204):
                print("agenthub: loki push %s -> HTTP %s" % (agent, r.getcode()), flush=True)
            else:
                print("agenthub: loki push %s %s ok" % (agent, rep["id"]), flush=True)
    except Exception as e:
        print("agenthub: loki push %s failed: %s" % (agent, e), flush=True)


def loki_loop():
    while True:
        for agent in REPORT_DIRS:
            rep = latest(agent)
            if rep is None:
                continue
            with _LOCK:
                if _PUSHED.get(agent) == rep["id"]:
                    continue
            push_loki(rep)
            with _LOCK:
                _PUSHED[agent] = rep["id"]
        time.sleep(POLL)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, text, ctype="text/plain"):
        b = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/metrics", "/metrics/"):
            self._send(200, render_metrics(), "text/plain; version=0.0.4")
        elif self.path in ("/", "/healthz"):
            self._send(200, "ok\n")
        else:
            self._send(404, "not found\n")

    def log_message(self, *a):
        pass


def main():
    if LOKI_ON:
        threading.Thread(target=loki_loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("agenthub: listening on :%d (loki=%s)" % (PORT, "on" if LOKI_ON else "off"), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
