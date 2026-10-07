# secnews-agent: daily cybersecurity news briefing

Part of [mikes-agents](../README.md).

Built 2026-10-07. Runs on **192.168.1.98** (hv-rocky-linux-1, observability hub).

Every day at 06:00 (America/Chicago) it pulls the last 24 hours of cybersecurity news plus newly added
CISA Known Exploited Vulnerabilities, has the local LLM triage and summarize them, saves an HTML report and
emails it to mcropsey@gmail.com. It can also be run by hand at any time.

## Architecture

```
 .98 hv-rocky-linux-1                     .101 hv-rocky-linux-4           .194 (RTX 5090)
 ┌──────────────────────────┐             ┌──────────────────────┐        ┌───────────────────┐
 │ secnews.timer (06:00)    │             │ LiteLLM :4000        │        │ LM Studio :1234   │
 │   └ secnews.service      │  HTTP POST  │  key: secnews-agent  │  HTTP  │  qwen/qwen3.8-27b │
 │       └ podman run       ├────────────►│  agent: secnews-agent├───────►│                   │
 │         localhost/secnews│ /v1/chat/   │  model: qwen3.8-27b  │        └───────────────────┘
 │ `secnews` (manual run)   │ completions └──────────────────────┘
 └─────────┬───────┬────────┘
           │       └──── HTTPS ──► RSS feeds + CISA KEV JSON (internet)
           └────────── SMTPS :465 ──► smtp.gmail.com ──► mcropsey@gmail.com
```

One run = feed fetch (~10 s) + **one** LLM call (~4k tokens in, 8-12k out including reasoning,
60-100 s on the 5090) + one email.

## Sources

| Source | URL |
|---|---|
| BleepingComputer | https://www.bleepingcomputer.com/feed/ |
| The Hacker News | https://feeds.feedburner.com/TheHackersNews |
| Krebs on Security | https://krebsonsecurity.com/feed/ |
| SecurityWeek | https://www.securityweek.com/feed/ |
| Dark Reading | https://www.darkreading.com/rss.xml |
| The Record | https://therecord.media/feed |
| SANS ISC | https://isc.sans.edu/rssfeed_full.xml |
| CISA Advisories | https://www.cisa.gov/cybersecurity-advisories/all.xml |
| Schneier on Security | https://www.schneier.com/feed/atom/ |
| CISA KEV catalog | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |

Articles older than the look-back window (default 24 h) are dropped, duplicate headlines are merged, and the
newest 45 are sent to the model. KEV entries are those whose `dateAdded` falls within the window (min. 1 day).

## Files on .98

| Path | Purpose |
|---|---|
| `/opt/secnews/app/secnews.py` | The agent |
| `/opt/secnews/app/Containerfile` | Image build: python:3.12-slim + feedparser + httpx  |
| `/opt/secnews/secnews.env` | Config + secrets, root-only, mode 600 (template: `secnews.env.example`) |
| `/opt/secnews/data/reports/` | `YYYY-MM-DD_HHMM.html` + `.json` per run; `latest.html` = newest |
| `/usr/local/bin/secnews` | Manual-run wrapper  |
| `/etc/systemd/system/secnews.service` | Oneshot unit that runs the container  |
| `/etc/systemd/system/secnews.timer` | Daily 06:00 schedule, `Persistent=true`  |
| image `localhost/secnews:latest` | Rootful podman image |

## Usage

```bash
ssh 192.168.1.98
secnews                      # run now and email
secnews --no-email           # save the report only
secnews --hours 72           # longer look-back (e.g. Monday catch-up)
secnews --to someone@x.com   # different recipient

sudo systemctl start secnews.service   # run exactly like the timer does
journalctl -u secnews -f               # logs of scheduled runs
systemctl list-timers secnews.timer    # next scheduled run
```

## Configuration (`/opt/secnews/secnews.env`)

| Variable | Value | Notes |
|---|---|---|
| `LITELLM_URL` | `http://192.168.1.101:4000/v1` | LiteLLM gateway |
| `LITELLM_API_KEY` | `sk-...YStw` | Virtual key alias `secnews-agent` |
| `MODEL` | `qwen3.8-27b` | Only model the key may use |
| `MAIL_TO` | `mcropsey@gmail.com` | Default recipient |
| `SMTP_USER` | `mcropsey@gmail.com` | Gmail account that sends |
| `SMTP_PASS` | *(Gmail app password)* | 16 chars, from https://myaccount.google.com/apppasswords |

Edit with `sudo vi /opt/secnews/secnews.env`; changes apply to the next run (no rebuild needed).
If `SMTP_PASS` is empty, runs still save the report and skip the email.

## LiteLLM setup (on .101)

- **Virtual key** `secnews-agent`: `models: ["qwen3.8-27b"]`, `max_parallel_requests: 1`, `rpm_limit: 30`,
  metadata tag `secnews`. Restricting the model means the agent can never make LM Studio load a second model
  next to qwen3.8 (which would push it to CPU).
- **Agent registry** entry `secnews-agent` (agent_id `54c73c96-…`), name "Cybersecurity News Digest
  (secnews-agent)", skills *news-triage* and *kev-watch*, `object_permission.models = ["qwen3.8-27b"]`.
  The key is linked via `agent_id`, so traffic is attributed to the agent on the LiteLLM *Agents* page.
- Each request carries `metadata.tags = ["secnews"]` and `user = "secnews-agent@192.168.1.98"`.
- Key metadata `opted_out_global_guardrails: ["basic-safety-filter"]`: the lab-wide content filter blocks
  security vocabulary that is normal in security news. The filter still applies to all other keys.
- Spend shows $0.00 because the `qwen3.8-27b` route has no price configured.

To (re)create both, use [../litellm/register_agent.py](../litellm/) with alias `secnews-agent`.

## Install from scratch

On .98 (as a sudo user), from this folder:

```bash
sudo mkdir -p /opt/secnews/app /opt/secnews/data && sudo chmod 700 /opt/secnews
sudo cp secnews.py Containerfile /opt/secnews/app/
sudo install -m 600 secnews.env.example /opt/secnews/secnews.env   # then fill in the key + app password
sudo install -m 755 secnews /usr/local/bin/secnews
sudo cp secnews.service secnews.timer /etc/systemd/system/
sudo podman build -t localhost/secnews:latest -f /opt/secnews/app/Containerfile /opt/secnews/app
sudo systemctl daemon-reload && sudo systemctl enable --now secnews.timer
secnews --no-email   # test
```

LiteLLM key (on .101), if recreating: see [../litellm/README.md](../litellm/README.md) (spec for
`secnews-agent` is in the table there). Put the key into `LITELLM_API_KEY` in `/opt/secnews/secnews.env`.

To change the code: edit `/opt/secnews/app/secnews.py`, then rebuild the image (the `podman build` line above).

## How the agent works (secnews.py)

1. **fetch()**: downloads each feed with httpx, parses with feedparser, filters by age, de-duplicates by
   normalized title, keeps the newest 45. Downloads the KEV JSON and keeps recent additions. Feeds that fail
   are listed in the report footer instead of stopping the run.
2. **ask_llm()**: one chat completion to LiteLLM with a system prompt asking for a ranked JSON briefing
   (headline, summary, 8-15 stories with severity/category/summary/action/CVEs/source numbers, KEV notes).
   `max_tokens` 24000 and a second attempt if the reply is empty or not valid JSON (see troubleshooting).
3. **render()**: builds an inline-styled HTML email (colour bar per severity, links to the source articles,
   KEV table with NVD links).
4. Saves `.html` + `.json` to `/data/reports` (bind-mounted from `/opt/secnews/data`), then emails via
   `smtplib.SMTP_SSL("smtp.gmail.com", 465)`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `no JSON in model reply: ''` | qwen3.8's reasoning used up `max_tokens` before it answered. Limit raised 12k → 24k with one retry (2026-10-07). If it recurs, raise again. |
| `CISA Advisories (HTTPStatusError)` in footer | cisa.gov's CDN 403s browser-like user agents from scripts. cisa.gov URLs are fetched with a `curl/7.76.1` user agent. |
| Email auth error (`535`) | App password revoked or the Google password was changed (that revokes all app passwords). Create a new one and update `SMTP_PASS`. |
| `Content blocked: ...` (HTTP 400) | Key lost its guardrail opt-out; see the LiteLLM setup above. |
| `401`/`403` from LiteLLM | Key deleted or model list changed; check key `secnews-agent` in the LiteLLM UI. |
| Very slow LLM step | Another model loaded in LM Studio next to qwen3.8; unload it. |
| No email at 06:00 | `journalctl -u secnews --since today`. A failed run sends nothing. |

## Known limits / possible next steps

- A failed scheduled run sends no email (could add a failure notice).
- Single LLM call over raw httpx, no tools. The lab agents (labwatch etc.) use the OpenAI SDK, send
  `X-Agent-Name` headers and labwatch runs a real tool-calling loop; secnews could be moved to the same
  shared code if agent-discovery tooling should classify it the same way.
- Reports are never pruned (~50 KB/day).
