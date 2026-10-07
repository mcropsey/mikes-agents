"""Shared plumbing for the lab agents: LiteLLM client, JSON answers, tool loop, reports, email."""
import datetime as dt
import html
import json
import os
import re
import smtplib
import time
from email.message import EmailMessage
from pathlib import Path

from openai import OpenAI

LITELLM_URL = os.environ.get("LITELLM_URL", "http://192.168.1.101:4000/v1")
MODEL = os.environ.get("MODEL", "qwen3.8-27b")
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "").replace(" ", "")
MAIL_TO = os.environ.get("MAIL_TO", "mcropsey@gmail.com")
DATA = Path(os.environ.get("DATA_DIR", "/data"))
HOST = "192.168.1.98"

# Lab host map, given to the models so they can name hosts properly.
LAB_HOSTS = """\
192.168.1.85  rasp5             Raspberry Pi 5, control node, Twingate
192.168.1.98  hv-rocky-linux-1  observability hub (Prometheus/Grafana/Loki/Alertmanager), VulnNotes API, these agents
192.168.1.99  hv-rocky-linux-2  k3s cluster + Cloudflare tunnel ingress, Noname sensor
192.168.1.100 hv-rocky-linux-3  Kong gateway + Jenkins CI
192.168.1.101 hv-rocky-linux-4  LiteLLM AI gateway, crAPI + Juice Shop labs, Noname sensor (RAM-tight)
192.168.1.102 hv-rocky-linux-5  Noname sensor, MCP servers (crapi/noname/vampi), AI simulator
192.168.1.103 hv-rocky-linux-6  RHCSA practice workstation
192.168.1.104 hv-rocky-linux-7  RHCSA practice workstation
192.168.1.105 utility.lab       RHCSA utility server (dnf repo mirror + NFS)
192.168.1.75  rk1               Raspberry Pi 5, microk8s node
192.168.1.76  rk2               Raspberry Pi 5, microk8s node
192.168.1.77  rk3               spare, RESERVED by the owner (powered off / down is expected)
192.168.1.78  rk4               spare, RESERVED by the owner (down is expected)
192.168.1.194 (GPU box)         LM Studio on an RTX 5090 serving qwen3.8-27b (not monitored)"""


class Agent:
    """One agent run: an OpenAI-compatible client on the agent's own LiteLLM key, plus call stats."""

    def __init__(self, name: str):
        self.name = name
        self.calls = 0
        self.tool_calls = 0
        self.tokens = 0
        self.started = time.monotonic()
        self.client = OpenAI(
            base_url=LITELLM_URL,
            api_key=os.environ[f"{name.split('-')[0].upper()}_KEY"],
            default_headers={"X-Agent-Name": name, "X-Agent-Host": HOST},
            timeout=1200,
            max_retries=2,
        )

    def _chat(self, messages, **kw):
        resp = self.client.chat.completions.create(
            model=MODEL, messages=messages, temperature=0.2, max_tokens=24000,
            user=f"{self.name}@{HOST}", extra_body={"metadata": {"tags": [self.name]}}, **kw)
        self.calls += 1
        self.tokens += resp.usage.total_tokens if resp.usage else 0
        return resp.choices[0]

    def ask_json(self, system: str, user: str) -> dict:
        """One question, JSON answer. qwen3.8's reasoning counts against max_tokens, so retry once if cut off."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for attempt in (1, 2):
            choice = self._chat(messages)
            parsed = parse_json(choice.message.content)
            if parsed is not None:
                return parsed
            log(f"attempt {attempt}: unusable reply (finish_reason={choice.finish_reason})")
        raise ValueError("model gave no JSON answer")

    def run_tools(self, system: str, user: str, tools: list, handlers: dict, max_rounds: int = 8) -> dict:
        """Tool-calling loop: the model may call tools up to max_rounds times, then must answer in JSON."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for _ in range(max_rounds):
            choice = self._chat(messages, tools=tools)
            msg = choice.message
            if not msg.tool_calls:
                parsed = parse_json(msg.content)
                if parsed is not None:
                    return parsed
                messages.append({"role": "assistant", "content": msg.content or ""})
                messages.append({"role": "user", "content": "Reply now with ONLY the final JSON object."})
                continue
            messages.append({"role": "assistant", "content": msg.content or "",
                             "tool_calls": [tc.model_dump() for tc in msg.tool_calls]})
            for tc in msg.tool_calls:
                self.tool_calls += 1
                try:
                    args = json.loads(tc.function.arguments or "{}")
                    result = handlers[tc.function.name](**args)
                except Exception as e:  # tool errors go back to the model, not up the stack
                    result = f"ERROR: {type(e).__name__}: {e}"
                log(f"tool {tc.function.name}({tc.function.arguments[:120]}) -> {len(str(result))} chars")
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(result)[:6000]})
        messages.append({"role": "user", "content": "Tool budget used up. Reply now with ONLY the final JSON object."})
        parsed = parse_json(self._chat(messages).message.content)
        if parsed is None:
            raise ValueError("model gave no JSON answer after tool loop")
        return parsed

    def footer(self, extra: str = "") -> str:
        return (f"{self.name} on {HOST} · model {MODEL} via LiteLLM · {self.calls} LLM calls, "
                f"{self.tool_calls} tool calls, {self.tokens:,} tokens, {time.monotonic() - self.started:.0f}s"
                + (f" · {extra}" if extra else ""))


def parse_json(text):
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S)
    match = re.search(r"\{.*\}", text, re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def log(msg: str) -> None:
    print(f"{dt.datetime.now():%H:%M:%S} {msg}", flush=True)


# ---------- HTML ----------

SEV_COLOR = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08800", "low": "#4a5568",
             "info": "#2b6cb0", "red": "#b42318", "yellow": "#b08800", "green": "#2f855a"}
e = lambda s: html.escape(str(s if s is not None else ""))


def card(severity: str, title: str, body: str, meta: str = "") -> str:
    color = SEV_COLOR.get(str(severity).lower(), "#4a5568")
    return (f'<div style="border-left:4px solid {color};padding:6px 12px;margin:12px 0">'
            f'<div style="font-size:12px;color:{color};font-weight:600;text-transform:uppercase">'
            f'{e(severity)}{" · " + e(meta) if meta else ""}</div>'
            f'<div style="font-weight:600;font-size:15px;margin:2px 0">{e(title)}</div>{body}</div>')


def table(headers: list, rows: list) -> str:
    th = "".join(f'<th style="text-align:left;padding:4px 8px;border-bottom:1px solid #cbd5e0">{e(h)}</th>'
                 for h in headers)
    trs = "".join("<tr>" + "".join(f'<td style="padding:3px 8px;border-bottom:1px solid #edf2f7;'
                                   f'vertical-align:top">{c}</td>' for c in r) + "</tr>" for r in rows)
    return f'<table style="border-collapse:collapse;font-size:13px;margin:8px 0">{"<tr>" + th + "</tr>"}{trs}</table>'


def page(title: str, inner: str, footer: str) -> str:
    return (f'<html><body style="font-family:-apple-system,Segoe UI,Arial,sans-serif;max-width:820px;'
            f'margin:auto;color:#1a202c;line-height:1.45"><h2 style="margin-bottom:4px">{e(title)}</h2>{inner}'
            f'<p style="font-size:12px;color:#718096;margin-top:24px">{e(footer)}</p></body></html>')


# ---------- output ----------

def save_report(agent: str, body_html: str, data: dict) -> Path:
    out = DATA / "reports" / agent
    out.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M")
    (out / f"{stamp}.html").write_text(body_html)
    (out / f"{stamp}.json").write_text(json.dumps(data, indent=2, default=str))
    (out / "latest.html").write_text(body_html)
    log(f"saved {out / (stamp + '.html')}")
    return out / f"{stamp}.html"


def send_mail(subject: str, body_html: str, to: str = MAIL_TO) -> None:
    if not (SMTP_USER and SMTP_PASS):
        log("email skipped: SMTP_USER/SMTP_PASS not set")
        return
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, SMTP_USER, to
    msg.set_content("This report is HTML; open it in an HTML-capable mail client.")
    msg.add_alternative(body_html, subtype="html")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=60) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
    log(f"emailed {to}")


def load_inventory(max_age_hours: int = 72) -> tuple[dict, str]:
    """Latest inventory from labinventory; returns (inventory, warning-or-empty)."""
    path = DATA / "inventory" / "latest.json"
    if not path.exists():
        raise SystemExit(f"no inventory at {path}; run `labinventory` first")
    inv = json.loads(path.read_text())
    age = (time.time() - inv["collected_ts"]) / 3600
    warn = f"inventory is {age:.0f}h old" if age > max_age_hours else ""
    return inv, warn
