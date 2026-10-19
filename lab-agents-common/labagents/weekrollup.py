"""weekrollup-agent: weekly digest of every lab agent's reports, plus a quality check.

Reads the last N days (default 7) of saved report JSON from every agent, builds a compact timeline, and asks
the model for: the week's story, issues that recurred or stayed open, and a short QUALITY CHECK that looks for
reports that contradict themselves or the data (e.g. labwatch called it GREEN while a target was down, or an
"affected" CVE finding with no action). Emails a Friday digest. Read-only; no inventory or SSH.

Usage: python -m labagents.weekrollup [--days N] [--no-email] [--to ADDR]
"""
import argparse
import datetime as dt
import json
import os
import re
import time
from pathlib import Path

from .common import DATA, MAIL_TO, Agent, card, e, log, page, save_report, send_mail, table

# Where each agent writes its reports (same paths agenthub reads).
REPORT_DIRS = {
    "labwatch": DATA / "reports" / "labwatch",
    "cvewatch": DATA / "reports" / "cvewatch",
    "patchwatch": DATA / "reports" / "patchwatch",
    "servicemap": DATA / "reports" / "servicemap",
    "alertwatch": DATA / "reports" / "alertwatch",
    "secnews": Path(os.environ.get("SECNEWS_REPORTS", "/opt/secnews/data/reports")),
}
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})_(\d{4})\.json$")

SYSTEM = """You are the lab's weekly reviewer. You get a week of machine summaries from the lab's own agents
(health, CVE matching, patch planning, service-map changes, alert triage, security news). Write the owner a
tight weekly digest AND a quality check of the agents themselves.

Reply with ONLY this JSON:
{"headline": "one sentence on the week",
 "summary": "4-6 sentences: health trend, notable CVEs/patches, service changes, alert activity, news themes",
 "themes": [{"area": "health|cve|patch|servicemap|alerts|news", "title": "...", "detail": "what happened across the week, with dates/numbers"}],
 "open_items": [{"title": "still open / recurring", "detail": "why it matters", "action": "next step"}],
 "quality": [{"agent": "which agent", "issue": "report that looks wrong or inconsistent", "evidence": "the contradicting detail", "severity": "high|medium|low"}]}
If an agent's reports look fine all week, say so with one low-severity quality note rather than inventing problems."""


def load_week(days: int) -> dict:
    cutoff = time.time() - days * 86400
    out = {}
    for agent, d in REPORT_DIRS.items():
        runs = []
        try:
            names = os.listdir(d)
        except OSError:
            out[agent] = []
            continue
        for n in sorted(names):
            m = STAMP.match(n)
            if not m or os.path.getmtime(d / n) < cutoff:
                continue
            try:
                data = json.loads((d / n).read_text())
            except Exception:
                continue
            res = data.get("result") if isinstance(data.get("result"), dict) else data
            runs.append({"when": f"{m.group(1)} {m.group(2)[:2]}:{m.group(2)[2:]}", "result": _slim(agent, res, data)})
        out[agent] = runs
    return out


def _slim(agent: str, res: dict, data: dict) -> dict:
    """Keep only the fields that carry the weekly signal, so the whole week fits in one prompt."""
    if agent == "labwatch":
        return {"status": res.get("status"), "headline": res.get("headline"),
                "issues": [{"sev": i.get("severity"), "host": i.get("host"), "title": i.get("title")}
                           for i in res.get("issues", [])]}
    if agent == "cvewatch":
        return {"summary": res.get("summary"),
                "affected": [{"product": f.get("product"), "sev": f.get("severity"), "cves": f.get("cves"),
                              "action": f.get("action")} for f in res.get("findings", []) if f.get("verdict") == "affected"]}
    if agent == "patchwatch":
        return {"headline": res.get("headline"),
                "priorities": [{"priority": p.get("priority"), "title": p.get("title"), "hosts": p.get("hosts")}
                               for p in res.get("priorities", [])]}
    if agent == "servicemap":
        ch = data.get("changes") or {}
        return {"change_summary": data.get("change_summary"),
                "counts": {k: len(ch.get(k) or []) for k in ("added", "removed", "changed")}}
    if agent == "alertwatch":
        return {"status": res.get("status"), "headline": res.get("headline"),
                "alerts": [{"name": a.get("alertname"), "sev": a.get("severity"), "real": a.get("real")}
                           for a in res.get("alerts", [])]}
    if agent == "secnews":
        return {"headline": data.get("headline"),
                "stories": [{"sev": s.get("severity"), "title": s.get("title")} for s in data.get("stories", [])][:8]}
    return res


def render(result: dict, week: dict, footer: str, days: int) -> str:
    parts = [f'<p style="font-size:16px"><b>{e(result.get("headline"))}</b></p><p>{e(result.get("summary"))}</p>']
    if result.get("themes"):
        parts.append("<h3>This week</h3>" + "".join(
            card("info", t.get("title", ""), f'<div>{e(t.get("detail"))}</div>', t.get("area", "")) for t in result["themes"]))
    if result.get("open_items"):
        parts.append("<h3>Still open</h3>" + "".join(
            card("medium", o.get("title", ""),
                 f'<div>{e(o.get("detail"))}</div>'
                 + (f'<div style="margin-top:4px"><b>Action:</b> {e(o["action"])}</div>' if o.get("action") else ""))
            for o in result["open_items"]))
    if result.get("quality"):
        parts.append("<h3>Agent quality check</h3>" + table(
            ["Agent", "Severity", "Issue", "Evidence"],
            [[e(q.get("agent")), e(q.get("severity")), e(q.get("issue")), e(q.get("evidence"))]
             for q in result["quality"]]))
    parts.append("<h3>Runs counted</h3>" + table(
        ["Agent", "Runs this week"], [[e(a), e(len(r))] for a, r in week.items()]))
    return page(f"Lab weekly digest: {dt.date.today() - dt.timedelta(days=days):%b %d} - {dt.date.today():%b %d}",
                "".join(parts), footer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to")
    args = ap.parse_args()

    week = load_week(args.days)
    counts = {a: len(r) for a, r in week.items()}
    log(f"loaded {sum(counts.values())} reports over {args.days}d: {counts}")

    agent = Agent("weekrollup-agent")
    result = agent.ask_json(SYSTEM, "A week of lab agent reports (newest last per agent):\n"
                            + json.dumps(week, indent=1, default=str))
    log(f"{len(result.get('themes', []))} themes, {len(result.get('open_items', []))} open items, "
        f"{len(result.get('quality', []))} quality notes")
    body = render(result, week, agent.footer(), args.days)
    save_report("weekrollup", body, {"result": result, "counts": counts})
    if not args.no_email:
        send_mail(f"Lab weekly digest: {result.get('headline', '')[:90]}", body, args.to or MAIL_TO)


if __name__ == "__main__":
    main()
