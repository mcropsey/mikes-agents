"""patchrun-agent: apply the OS security updates that patchwatch recommends, with human approval.

patchwatch writes the plan; patchrun carries it out. It is deliberately conservative:

  * DRY-RUN BY DEFAULT. With no --approve it only *simulates* on every host (dnf check-update --security /
    apt-get -s upgrade) and reports what would change. Nothing is modified.
  * APPROVAL IS TIED TO THE PLAN. --approve <token> actually applies. The token is derived from the latest
    patchwatch report id, so an approval only matches the plan it was issued for; a newer plan needs a new token.
    Run with --dry-run (the default) to see the token to approve.
  * SECURITY UPDATES ONLY unless --all. It never reboots - that is ops/lab-reboots.sh, run separately - but it
    reports which hosts now need one.
  * The intentionally-vulnerable lab containers (crAPI/Juice Shop/VAmPI/DVGA) are never touched: this patches
    host OS packages only, not containers.

Hosts, order and OS come from the latest labinventory. After the run the model writes a plain-English result
summary. Needs passwordless SSH + `sudo -n` from mcropsey@.98 to every host (same as labinventory/servicemap).

Usage:
  python -m labagents.patchrun                      # dry-run on all hosts, prints the approval token
  python -m labagents.patchrun --approve <token>    # apply security updates to all hosts in the plan
  python -m labagents.patchrun --approve <token> --all --hosts 192.168.1.103,192.168.1.104
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from .common import DATA, LAB_HOSTS, MAIL_TO, Agent, card, e, load_inventory, log, page, save_report, send_mail, table

# Patch .98 last (it hosts this agent + the monitoring stack); internet-facing / shared services late.
ORDER = ["192.168.1.103", "192.168.1.104", "192.168.1.105", "192.168.1.102", "192.168.1.100",
         "192.168.1.99", "192.168.1.101", "192.168.1.85", "192.168.1.75", "192.168.1.76", "192.168.1.98"]
# Runs inside the labagents container as root, so SSH out as the lab user with the key mounted at /root/.ssh.
# -F /dev/null ignores the mounted user ssh_config (root won't accept a non-root-owned config file); the key
# and known_hosts are named explicitly instead.
SSH_USER = os.environ.get("PATCHRUN_SSH_USER", "mcropsey")
SSH_KEY = os.environ.get("PATCHRUN_SSH_KEY", "/root/.ssh/id_ed25519")
SSH = ["ssh", "-n", "-F", "/dev/null", "-l", SSH_USER, "-i", SSH_KEY,
       "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
       "-o", "UserKnownHostsFile=/root/.ssh/known_hosts", "-o", "StrictHostKeyChecking=accept-new"]
PATCHWATCH = DATA / "reports" / "patchwatch"

SYSTEM = f"""You are the lab's patch operator reporting the result of a patch run to the owner.

Lab hosts:
{LAB_HOSTS}

You get, per host: the OS, whether this was a dry-run or a real apply, the packages that were updated (or would
be), security-update counts before/after, whether a reboot is now needed, and any errors. Write a clear result
report. Call out hosts that failed, that still have pending security updates, or that now need a reboot (note
that reboots are done separately by ops/lab-reboots.sh). Keep it factual.

Reply with ONLY this JSON:
{{"status": "ok|attention|failed",
 "headline": "one sentence",
 "summary": "3-4 sentences on what happened across the lab",
 "hosts": [{{"host": "name (ip)", "result": "patched N / dry-run / no updates / failed", "reboot_needed": true,
            "note": "anything to follow up"}}],
 "followups": ["concrete next steps, e.g. which hosts to reboot and when"]}}
status ok = clean, attention = pending updates or reboots remain, failed = at least one host errored."""


def ssh(ip: str, cmd: str, timeout: int = 900) -> tuple[int, str]:
    try:
        p = subprocess.run(SSH + [ip, cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"
    except Exception as ex:
        return 1, f"{type(ex).__name__}: {ex}"


# Security updates dnf would install, counted as root with fresh metadata (the same view the apply step
# gets). Skip the informational "Security: kernel-core-... is an installed security update" lines.
DNF_SEC = "sudo -n dnf -q --refresh check-update --security 2>/dev/null | grep -v '^Security:'"


def is_debian(os_name: str) -> bool:
    return any(s in (os_name or "").lower() for s in ("ubuntu", "debian"))


def plan_token(report_id: str) -> str:
    return hashlib.sha256(f"patchrun:{report_id}".encode()).hexdigest()[:8]


def latest_patchwatch() -> tuple[str, dict]:
    try:
        files = sorted(f for f in PATCHWATCH.iterdir() if f.suffix == ".json")
    except OSError:
        files = []
    if not files:
        return "no-plan", {}
    rid = files[-1].stem
    try:
        return rid, json.loads(files[-1].read_text())
    except Exception:
        return rid, {}


def host_run(ip: str, name: str, os_name: str, apply: bool, all_pkgs: bool) -> dict:
    deb = is_debian(os_name)
    rec = {"ip": ip, "host": f"{name} ({ip})", "os": os_name, "applied": apply, "error": "", "updated": [], "reboot": None}

    if deb:
        rc, out = ssh(ip, "sudo -n apt-get update -qq >/dev/null 2>&1; apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | wc -l")
        rec["pending_before"] = out.strip().split("\n")[-1] if rc == 0 else "?"
    else:
        rc, out = ssh(ip, f"n=$({DNF_SEC} | grep -cE '^[a-zA-Z0-9]'); echo $n")
        rec["pending_before"] = out.strip().split("\n")[-1] if out.strip() else "0"

    if not apply:
        if deb:
            rc, out = ssh(ip, "apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | sed 's/^Inst //' | head -40", 120)
        else:
            rc, out = ssh(ip, f"{DNF_SEC} | awk 'NF>=3{{print $1}}' | head -40", 120)
        rec["updated"] = [l for l in out.splitlines() if l.strip()]
        rec["result"] = f"dry-run: {len(rec['updated'])} package(s) would update"
        return rec

    # Apply (security only unless --all).
    if deb:
        cmd = ("sudo -n sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
               + ("apt-get -y upgrade" if all_pkgs else "apt-get -y -o Dir::Etc::SourceList=/etc/apt/sources.list "
                  "upgrade") + " 2>&1' | tail -40")
    else:
        cmd = f"sudo -n dnf -y --refresh update {'' if all_pkgs else '--security'} 2>&1 | tail -40"
    rc, out = ssh(ip, cmd)
    rec["error"] = "" if rc == 0 else f"rc={rc}"
    rec["apply_tail"] = out.strip().splitlines()[-12:]

    # Pending after + reboot flag.
    if deb:
        rc2, o2 = ssh(ip, "apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | wc -l; test -f /var/run/reboot-required && echo REBOOT")
    else:
        rc2, o2 = ssh(ip, f"{DNF_SEC} | grep -cE '^[a-zA-Z0-9]'; "
                          "test \"$(rpm -q --last kernel-core 2>/dev/null | head -1 | awk '{print $1}' | sed s/kernel-core-//)\" != \"$(uname -r)\" && echo REBOOT")
    lines = o2.splitlines()
    rec["pending_after"] = lines[0].strip() if lines else "?"
    rec["reboot"] = any("REBOOT" in l for l in lines)
    before, after = rec.get("pending_before", "?"), rec["pending_after"]
    if rec["error"]:
        rec["result"] = "failed"
    elif after.isdigit() and int(after) > 0:
        rec["result"] = "no change" if after == before else "partial"
    else:
        rec["result"] = "patched"
    return rec


def render(result: dict, runs: list, apply: bool, token: str, footer: str) -> str:
    status = str(result.get("status", "attention")).lower()
    color = {"ok": "#2f855a", "attention": "#b08800", "failed": "#b42318"}.get(status, "#4a5568")
    banner = (f'<p style="font-size:16px"><span style="background:{color};color:#fff;padding:2px 8px;'
              f'border-radius:4px;font-weight:600">{e(status.upper())}</span> <b>{e(result.get("headline"))}</b></p>'
              f'<p>{e(result.get("summary"))}</p>')
    mode = ('<p style="background:#fffbea;border:1px solid #f0e3a0;padding:8px 12px;border-radius:6px">'
            + ("<b>Applied</b> security updates (approval token used)." if apply else
               f"<b>Dry-run only</b> - nothing was changed. To apply this plan: "
               f"<code>patchrun --approve {e(token)}</code>") + "</p>")
    fu = ("<h3>Follow-ups</h3><ul>" + "".join(f"<li>{e(x)}</li>" for x in result.get("followups", [])) + "</ul>") \
        if result.get("followups") else ""
    rows = [[e(r["host"]), e(r.get("result")), e(f"{r.get('pending_before', '?')} -> {r.get('pending_after', '-')}"),
             ("yes" if r.get("reboot") else ("no" if r.get("reboot") is False else "-")),
             e(r.get("error") or "")] for r in runs]
    tbl = table(["Host", "Result", "Security pending", "Reboot needed", "Error"], rows)
    return page(f"Patch run {dt.datetime.now():%b %d %H:%M}", banner + mode + fu + "<h3>Hosts</h3>" + tbl, footer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--approve", metavar="TOKEN", help="apply (token from a dry-run); omit for dry-run")
    ap.add_argument("--all", action="store_true", help="all updates, not just security")
    ap.add_argument("--hosts", help="comma-separated IPs to limit to")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to")
    args = ap.parse_args()

    inv, inv_warn = load_inventory()
    rid, _plan = latest_patchwatch()
    token = plan_token(rid)
    apply = False
    if args.approve:
        if args.approve != token:
            raise SystemExit(f"approval token {args.approve!r} does not match the current plan ({rid}); "
                             f"run a dry-run to get the right token ({token}).")
        apply = True

    want = set(args.hosts.split(",")) if args.hosts else None
    hosts = [(ip, inv["hosts"][ip]) for ip in ORDER if ip in inv["hosts"] and (not want or ip in want)]
    log(f"patchrun {'APPLY' if apply else 'dry-run'} ({'all' if args.all else 'security'}) on {len(hosts)} host(s); plan {rid}")

    runs = []
    for ip, h in hosts:
        if h.get("error"):
            runs.append({"host": f"{h.get('name', ip)} ({ip})", "result": "skipped (unreachable in inventory)", "error": h["error"]})
            continue
        log(f"  {ip} ({h.get('name')}) ...")
        rec = host_run(ip, h.get("name", ip), h.get("os", ""), apply, args.all)
        log(f"    {rec.get('result')} err={rec.get('error') or '-'}")
        runs.append(rec)

    agent = Agent("patchrun-agent")
    payload = {"mode": "apply" if apply else "dry-run", "scope": "all" if args.all else "security", "plan_id": rid,
               "hosts": [{k: v for k, v in r.items() if k not in ("apply_tail",)} for r in runs]}
    result = agent.ask_json(SYSTEM, json.dumps(payload, indent=1, default=str))
    footer = agent.footer(f"plan {rid}" + (f" ({inv_warn})" if inv_warn else "") + (" APPLIED" if apply else " dry-run"))
    body = render(result, runs, apply, token, footer)
    save_report("patchrun", body, {"result": result, "runs": runs, "apply": apply, "plan_id": rid})
    if not args.no_email:
        send_mail(f"Patch run [{str(result.get('status', '?')).upper()}]: {result.get('headline', '')[:80]}",
                  body, args.to or MAIL_TO)


if __name__ == "__main__":
    main()
