#!/usr/bin/env python3
"""Web server for the lab service map and the lab agents' reports (stdlib only, read-only).

  /                    the service map site (index.html, SVGs, README.md, servicemap.json)
  /metrics             the map's Prometheus metrics (correct exposition Content-Type)
  /reports/            every agent's reports, newest first, with each run's headline
  /reports/<agent>/<file>   one report (.html or .json) from that agent's report folder

Report folders come from SERVICEMAP_REPORTS ("agent=/path,agent=/path"); servicemap-web.service bind-mounts them
read-only under /srv/reports so the sandboxed (DynamicUser) server never needs access to the agents' env files.
"""
import html
import json
import os
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("SERVICEMAP_WEB_PORT", "9440"))
SITE = os.environ.get("SERVICEMAP_SITE", "/opt/labagents/data/servicemap/site")
REPORTS = dict(kv.split("=", 1) for kv in os.environ.get(
    "SERVICEMAP_REPORTS",
    "labwatch=/srv/reports/labwatch,cvewatch=/srv/reports/cvewatch,patchwatch=/srv/reports/patchwatch,"
    "secnews=/srv/reports/secnews,servicemap=/srv/reports/servicemap,"
    "alertwatch=/srv/reports/alertwatch,weekrollup=/srv/reports/weekrollup,patchrun=/srv/reports/patchrun,"
    "agentdemo=/srv/reports/agentdemo,llmredteam=/srv/reports/llmredteam").split(",") if "=" in kv)
GRAFANA = os.environ.get("SERVICEMAP_GRAFANA", "http://192.168.1.98:3000")
ABOUT = {
    "labwatch": ("Lab health briefing", "daily 06:15"),
    "cvewatch": ("CVE-to-lab matcher", "daily 06:30"),
    "patchwatch": ("Patch & image drift plan", "daily 06:45"),
    "secnews": ("Cybersecurity news digest", "daily 06:00"),
    "servicemap": ("Lab service map", "daily 05:40"),
    "alertwatch": ("Alert triage (event-driven)", "on alert + daily 07:00"),
    "weekrollup": ("Weekly digest + agent quality check", "Fri 06:55"),
    "patchrun": ("Approved OS patch runs", "on demand"),
    "agentdemo": ("Safe vs hijacked agent demo", "on demand"),
    "llmredteam": ("LLM guardrail eval", "Sun 06:50"),
}
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})\.(html|json)$")
SAFE = re.compile(r"^[\w.-]+\.(html|json)$")
TYPES = {".html": "text/html; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml",
         ".md": "text/markdown; charset=utf-8", ".png": "image/png", ".css": "text/css", ".js": "text/javascript"}
e = lambda s: html.escape(str(s if s is not None else ""))
_headlines = {}


def headline(path: str) -> tuple:
    """(status, one-line headline) from a report's JSON, cached by mtime."""
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return "", ""
    hit = _headlines.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    status, text = "", ""
    try:
        with open(path) as fh:
            data = json.load(fh)
        res = data.get("result") if isinstance(data.get("result"), dict) else data
        status = str(res.get("status", "") or "")
        text = (res.get("headline") or data.get("headline") or data.get("change_summary") or res.get("summary")
                or data.get("summary") or "")
        if not status and isinstance(res.get("findings"), list):
            n = sum(1 for f in res["findings"] if isinstance(f, dict) and f.get("verdict") == "affected")
            status = f"{n} affected"
    except Exception:
        pass
    text = re.sub(r"\s+", " ", str(text)).strip()
    _headlines[path] = (mtime, (status, text[:220] + ("…" if len(text) > 220 else "")))
    return _headlines[path][1]


def runs(agent: str) -> list:
    d = REPORTS[agent]
    try:
        names = os.listdir(d)
    except OSError:
        return []
    by_stamp = {}
    for n in names:
        m = STAMP.match(n)
        if m:
            by_stamp.setdefault(f"{m.group(1)}_{m.group(2)}{m.group(3)}", set()).add(m.group(4))
    out = []
    for stamp in sorted(by_stamp, reverse=True):
        kinds = by_stamp[stamp]
        st, hl = headline(os.path.join(d, stamp + ".json")) if "json" in kinds else ("", "")
        out.append({"stamp": stamp, "kinds": kinds, "status": st, "headline": hl})
    return out


CSS = """
:root{--ground:#E9EDF1;--surface:#FFFFFF;--surface2:#F4F6F8;--ink:#141B23;--ink2:#3A4655;--muted:#58657A;--line:#CBD3DC;
  --good:#0ca30c;--warn:#B42318;--accent:#2a78d6;color-scheme:light}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){DARK}}
:root[data-theme="dark"]{DARK}
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font:14px/1.5 "IBM Plex Sans","Segoe UI",system-ui,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px 16px 48px}
h1,h2{font-family:"Chakra Petch","Segoe UI",system-ui,sans-serif;margin:0;text-wrap:balance}
h1{font-size:clamp(28px,4vw,40px)} h2{font-size:20px}
.eyebrow{font:12px "IBM Plex Mono",ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.lede{color:var(--ink2);max-width:80ch}
a{color:var(--accent)} .muted{color:var(--muted)}
.links{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 20px}
.links a{padding:5px 12px;border:1px solid var(--line);border-radius:99px;background:var(--surface);text-decoration:none;color:var(--ink)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:14px 0}
.card header{display:flex;flex-wrap:wrap;gap:6px 16px;align-items:baseline;justify-content:space-between}
.tablewrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:8px}
th{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:5px 8px;white-space:nowrap}
td{border-bottom:1px solid color-mix(in srgb,var(--line) 50%,transparent);padding:5px 8px;vertical-align:top}
td.when{white-space:nowrap;font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12px}
.st{font-weight:600;white-space:nowrap} .st.green{color:var(--good)} .st.red,.st.yellow{color:var(--warn)}
details summary{cursor:pointer;color:var(--muted);margin-top:6px}
"""
DARK = ("--ground:#0C1117;--surface:#141B24;--surface2:#1A2330;--ink:#E4E9EF;--ink2:#C3CCD6;--muted:#8F9CAD;"
        "--line:#2A3542;--warn:#FF8A7A;--accent:#6F9BFF;color-scheme:dark")


def index_page() -> str:
    cards = []
    for agent in REPORTS:
        rs = runs(agent)
        what, when = ABOUT.get(agent, (agent, ""))
        rows = []
        for i, r in enumerate(rs):
            day, hm = r["stamp"].split("_")
            links = " · ".join(f'<a href="/reports/{agent}/{r["stamp"]}.{k}">{k}</a>' for k in ("html", "json") if k in r["kinds"])
            st = r["status"]
            rows.append(f'<tr><td class="when">{e(day)} {e(hm[:2])}:{e(hm[2:])}</td>'
                        f'<td class="st {e(st.lower())}">{e(st)}</td><td>{e(r["headline"])}</td><td>{links}</td></tr>')
        head = '<table><tr><th>Run</th><th>Status</th><th>Headline</th><th>Report</th></tr>'
        body = head + "".join(rows[:14]) + "</table>"
        if len(rows) > 14:
            body += f'<details><summary>{len(rows) - 14} older runs</summary>{head}{"".join(rows[14:])}</table></details>'
        latest = (f'<a href="/reports/{agent}/{rs[0]["stamp"]}.html">latest report →</a>' if rs and "html" in rs[0]["kinds"]
                  else '<span class="muted">no reports yet</span>')
        cards.append(f'<section class="card" id="{e(agent)}"><header><h2>{e(agent)}</h2>'
                     f'<span class="muted">{e(what)} · {e(when)} · {len(rs)} runs</span>{latest}</header>'
                     f'<div class="tablewrap">{body if rs else ""}</div></section>')
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lab Agent Reports</title>'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<style>{CSS.replace("DARK", DARK)}</style>'
            '<script>var t=new URLSearchParams(location.search).get("theme");if(t)document.documentElement.setAttribute("data-theme",t)</script>'
            '</head><body><div class="wrap"><div class="eyebrow">Cropsey lab · mikes-agents</div>'
            '<h1>Lab agent reports</h1><p class="lede">Every report the scheduled lab agents on 192.168.1.98 have written, '
            f'newest first. Generated {time.strftime("%Y-%m-%d %H:%M")} (America/Chicago).</p>'
            '<div class="links">' + "".join(f'<a href="#{a}">{a}</a>' for a in REPORTS) +
            f'<a href="/">service map</a><a href="{GRAFANA}/d/agent-daily-reports">Grafana: Daily Reports</a>'
            f'<a href="{GRAFANA}/d/lab-service-map">Grafana: Lab Service Map</a></div>'
            + "".join(cards) + "</div></body></html>")


class Handler(BaseHTTPRequestHandler):
    server_version = "servicemap-web"

    def send(self, code, body: bytes, ctype="text/plain; charset=utf-8", head_only=False):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def file(self, path, ctype=None, head_only=False):
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            return self.send(404, b"not found\n", head_only=head_only)
        self.send(200, body, ctype or TYPES.get(os.path.splitext(path)[1], "application/octet-stream"), head_only)

    def route(self, head_only=False):
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path == "/metrics":
            return self.file(os.path.join(SITE, "metrics"), "text/plain; version=0.0.4; charset=utf-8", head_only)
        if path in ("/reports", "/reports/"):
            return self.send(200, index_page().encode(), "text/html; charset=utf-8", head_only)
        m = re.match(r"^/reports/([\w-]+)/([^/]+)$", path)
        if m:
            agent, name = m.groups()
            if agent in REPORTS and SAFE.match(name):
                return self.file(os.path.join(REPORTS[agent], name), head_only=head_only)
            return self.send(404, b"not found\n", head_only=head_only)
        name = path.lstrip("/") or "index.html"
        if "/" in name or name.startswith(".") or name == "metrics":
            return self.send(404, b"not found\n", head_only=head_only)
        return self.file(os.path.join(SITE, name), head_only=head_only)

    def do_GET(self):
        self.route()

    def do_HEAD(self):
        self.route(head_only=True)

    def log_message(self, fmt, *args):
        pass  # one line per Grafana image refresh is just noise in the journal


if __name__ == "__main__":
    print(f"servicemap-web: :{PORT} site={SITE} reports={','.join(REPORTS)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
