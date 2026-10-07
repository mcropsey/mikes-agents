"""Daily cybersecurity news digest.

Pulls security RSS feeds and the CISA KEV catalog, asks the local LLM (qwen3.8-27b via LiteLLM)
to triage and summarize, saves an HTML/Markdown report and emails it through Gmail SMTP.

Usage: secnews.py [--hours N] [--no-email] [--to ADDR]
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import smtplib
import sys
import time
from email.message import EmailMessage
from pathlib import Path

import feedparser
import httpx

LITELLM_URL = os.environ.get("LITELLM_URL", "http://192.168.1.101:4000/v1")
LITELLM_KEY = os.environ["LITELLM_API_KEY"]
MODEL = os.environ.get("MODEL", "qwen3.8-27b")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "").replace(" ", "")
MAIL_TO = os.environ.get("MAIL_TO", "mcropsey@gmail.com")
DATA = Path(os.environ.get("DATA_DIR", "/data"))
MAX_ARTICLES = 45

FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "The Record": "https://therecord.media/feed",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "CISA Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# cisa.gov's CDN returns 403 to browser-looking user agents from scripts, but allows a plain curl one.
CISA_HEADERS = {"User-Agent": "curl/7.76.1", "Accept": "*/*"}

SYSTEM = """You are a senior threat-intelligence analyst writing a morning cybersecurity briefing
for a security engineer who works on API security. You get a numbered list of recent articles and
newly added CISA Known Exploited Vulnerabilities. Merge duplicate stories, drop fluff/marketing,
and rank by real-world impact (active exploitation, widely deployed software, big breaches first).

Reply with ONLY a JSON object, no prose, in this shape:
{"headline": "one sentence: the single most important thing today",
 "summary": "3-4 sentence overview of the threat landscape today",
 "stories": [{"title": "...", "severity": "critical|high|medium|low",
              "category": "vulnerability|breach|ransomware|malware|nation-state|api-security|policy|other",
              "summary": "2-3 sentences: what happened and who is affected",
              "action": "one concrete recommended action, or empty string",
              "cves": ["CVE-..."], "sources": [article numbers]}],
 "kev_notes": "one or two sentences on the new KEV entries, or empty string"}
Include 8-15 stories. Use only facts from the provided articles."""


def clean(text, limit=450):
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(text or ""))).strip()
    return text[:limit]


def get(client, url):
    return client.get(url, headers=CISA_HEADERS if "cisa.gov" in url else None)


def fetch(client, hours):
    cutoff = time.time() - hours * 3600
    articles, failed = [], []
    for source, url in FEEDS.items():
        try:
            resp = get(client, url)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            failed.append(f"{source} ({type(e).__name__})")
            continue
        for e in feedparser.parse(resp.content).entries:
            ts = e.get("published_parsed") or e.get("updated_parsed")
            if ts and time.mktime(ts) < cutoff:
                continue
            articles.append({"source": source, "title": clean(e.get("title"), 200), "link": e.get("link", ""),
                             "summary": clean(e.get("summary") or e.get("description")),
                             "ts": time.mktime(ts) if ts else time.time()})
    seen, unique = set(), []
    for a in sorted(articles, key=lambda a: -a["ts"]):
        key = re.sub(r"\W+", "", a["title"].lower())[:60]
        if key not in seen:
            seen.add(key)
            unique.append(a)

    kev = []
    try:
        resp = get(client, KEV_URL)
        resp.raise_for_status()
        since = (dt.date.today() - dt.timedelta(days=max(1, hours // 24 + 1))).isoformat()
        kev = [v for v in resp.json().get("vulnerabilities", []) if v.get("dateAdded", "") >= since]
    except (httpx.HTTPError, ValueError) as e:
        failed.append(f"CISA KEV ({type(e).__name__})")
    return unique[:MAX_ARTICLES], kev, failed


def ask_llm(client, articles, kev):
    lines = [f"[{i + 1}] {a['source']}: {a['title']}\n{a['summary']}" for i, a in enumerate(articles)]
    kev_lines = [f"- {v['cveID']} {v['vendorProject']} {v['product']}: {v['vulnerabilityName']} "
                 f"(added {v['dateAdded']}, ransomware use: {v.get('knownRansomwareCampaignUse')})" for v in kev]
    prompt = ("ARTICLES:\n\n" + "\n\n".join(lines) +
              "\n\nNEW CISA KEV ENTRIES:\n" + ("\n".join(kev_lines) or "none"))
    # qwen3.8 reasons before answering and the reasoning counts against max_tokens (8-12k seen),
    # so leave plenty of room and retry once if the answer still comes back cut off or empty.
    for attempt in (1, 2):
        resp = client.post(f"{LITELLM_URL}/chat/completions", timeout=1200,
                           headers={"Authorization": f"Bearer {LITELLM_KEY}"},
                           json={"model": MODEL, "temperature": 0.2, "max_tokens": 24000,
                                 "messages": [{"role": "system", "content": SYSTEM},
                                              {"role": "user", "content": prompt}],
                                 "metadata": {"tags": ["secnews"]}, "user": "secnews-agent@192.168.1.98"})
        resp.raise_for_status()
        data = resp.json()
        choice = data["choices"][0]
        text = re.sub(r"<think>.*?</think>", "", choice["message"]["content"] or "", flags=re.S)
        match = re.search(r"\{.*\}", text, re.S)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        print(f"attempt {attempt}: unusable reply (finish_reason={choice.get('finish_reason')}, "
              f"completion_tokens={(data.get('usage') or {}).get('completion_tokens')})", flush=True)
    raise ValueError(f"no JSON in model reply: {text[:300]!r}")


SEV_COLOR = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08800", "low": "#4a5568"}


def render(digest, articles, kev, failed, today):
    def links(story):
        out = []
        for n in story.get("sources") or []:
            if isinstance(n, int) and 1 <= n <= len(articles):
                a = articles[n - 1]
                out.append(f'<a href="{html.escape(a["link"])}">{html.escape(a["source"])}</a>')
        return " · ".join(out)

    rows = []
    for s in digest.get("stories", []):
        sev = str(s.get("severity", "low")).lower()
        cves = ", ".join(s.get("cves") or [])
        rows.append(
            f'<div style="border-left:4px solid {SEV_COLOR.get(sev, "#4a5568")};padding:6px 12px;margin:14px 0">'
            f'<div style="font-size:12px;color:{SEV_COLOR.get(sev, "#4a5568")};font-weight:600;text-transform:uppercase">'
            f'{html.escape(sev)} · {html.escape(str(s.get("category", "")))}{" · " + html.escape(cves) if cves else ""}</div>'
            f'<div style="font-weight:600;font-size:15px;margin:2px 0">{html.escape(str(s.get("title", "")))}</div>'
            f'<div>{html.escape(str(s.get("summary", "")))}</div>'
            + (f'<div style="margin-top:4px"><b>Action:</b> {html.escape(str(s["action"]))}</div>' if s.get("action") else "")
            + f'<div style="font-size:12px;margin-top:4px">{links(s)}</div></div>')
    kev_rows = "".join(
        f'<li><a href="https://nvd.nist.gov/vuln/detail/{html.escape(v["cveID"])}">{html.escape(v["cveID"])}</a> '
        f'{html.escape(v["vendorProject"])} {html.escape(v["product"])}: {html.escape(v["vulnerabilityName"])} '
        f'(due {html.escape(v.get("dueDate", ""))})</li>' for v in kev)
    footer = f"{len(articles)} articles, {len(kev)} new KEV entries, model {MODEL}."
    if failed:
        footer += " Unreachable: " + ", ".join(failed) + "."
    return (f'<html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:760px;'
            f'margin:auto;color:#1a202c;line-height:1.45">'
            f'<h2 style="margin-bottom:4px">Cybersecurity briefing: {today}</h2>'
            f'<p style="font-size:16px"><b>{html.escape(str(digest.get("headline", "")))}</b></p>'
            f'<p>{html.escape(str(digest.get("summary", "")))}</p>{"".join(rows)}'
            + (f'<h3>New CISA KEV entries</h3><p>{html.escape(str(digest.get("kev_notes", "")))}</p><ul>{kev_rows}</ul>' if kev else "")
            + f'<p style="font-size:12px;color:#718096;margin-top:24px">{html.escape(footer)}</p></body></html>')


def send_mail(subject, body_html, to):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, SMTP_USER, to
    msg.set_content("This briefing is HTML; open it in an HTML-capable mail client.")
    msg.add_alternative(body_html, subtype="html")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=60) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24, help="look-back window (default 24)")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to", default=MAIL_TO)
    args = ap.parse_args()

    today = dt.datetime.now().strftime("%a %b %d, %Y %H:%M")
    started = time.monotonic()
    with httpx.Client(timeout=20, follow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0 (secnews-digest/1.0)"}) as client:
        articles, kev, failed = fetch(client, args.hours)
        print(f"fetched {len(articles)} articles, {len(kev)} KEV entries; failed: {failed or 'none'}", flush=True)
        if not articles and not kev:
            sys.exit("nothing fetched; aborting")
        digest = ask_llm(client, articles, kev)
    print(f"LLM done in {time.monotonic() - started:.0f}s: {len(digest.get('stories', []))} stories", flush=True)

    body = render(digest, articles, kev, failed, today)
    reports = DATA / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M")
    (reports / f"{stamp}.html").write_text(body)
    (reports / f"{stamp}.json").write_text(json.dumps(digest, indent=2))
    (reports / "latest.html").write_text(body)
    print(f"saved {reports / (stamp + '.html')}", flush=True)

    if args.no_email:
        return
    if not (SMTP_USER and SMTP_PASS):
        print("email skipped: SMTP_USER/SMTP_PASS not set in /opt/secnews/secnews.env", flush=True)
        return
    send_mail(f"Security briefing {dt.date.today()}: {digest.get('headline', '')[:90]}", body, args.to)
    print(f"emailed {args.to}", flush=True)


if __name__ == "__main__":
    main()
