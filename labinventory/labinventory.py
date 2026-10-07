#!/usr/bin/env python3
"""Lab software inventory collector (no LLM). Runs on .98 as mcropsey over the lab SSH key.

For every host in hosts.conf: OS, kernel, installed packages, pending updates, security advisories
(with CVEs), reboot-needed flag, running containers (with image digests) and Kubernetes pod images.
Writes DATA_DIR/inventory/<date>.json and latest.json. Used by cvewatch-agent and patchwatch-agent.

Usage: labinventory.py [--hosts FILE] [--only IP[,IP]]
Stdlib only (runs on the host's python3.9).
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(os.environ.get("LABAGENTS_HOME", "/opt/labagents"))
DATA = BASE / "data"

# Runs on each host via `ssh host bash -s`. Every block prints an "@@@ <section>" marker first.
REMOTE = r'''
sec(){ echo "@@@ $1"; }
sec os; . /etc/os-release; echo "$PRETTY_NAME"; uname -r; uptime -s
if command -v rpm >/dev/null 2>&1; then
  sec pm; echo rpm
  sec pkgs; rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'
  O="-q --setopt=skip_if_unavailable=True"
  sec updates; sudo -n timeout 400 dnf --setopt=skip_if_unavailable=True check-update 2>/tmp/.labinv.err
  sec update_errors; grep -iE "error|fail|ignoring" /tmp/.labinv.err | sort -u | head -10
  sec security; sudo -n timeout 300 dnf $O updateinfo list --security 2>/dev/null
  sec security_cves; sudo -n timeout 300 dnf $O updateinfo list --security --with-cve 2>/dev/null | grep '^CVE-'
  sec reboot
  if command -v needs-restarting >/dev/null 2>&1; then sudo -n needs-restarting -r >/dev/null 2>&1; echo $?
  else latest=$(rpm -q --last kernel-core 2>/dev/null | head -1 | awk '{print $1}' | sed 's/^kernel-core-//')
       if [ -z "$latest" ]; then echo unknown; elif [ "$latest" = "$(uname -r)" ]; then echo 0; else echo 1; fi; fi
else
  sec pm; echo dpkg
  sec pkgs; dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'
  sec update_errors; sudo -n timeout 300 apt-get update -qq 2>&1 >/dev/null | grep -E "^(E|W):" | head -10
  sec updates; apt list --upgradable 2>/dev/null | tail -n +2
  sec reboot; if [ -f /var/run/reboot-required ]; then echo 1; else echo 0; fi
fi
sec containers
for rt in "podman" "sudo -n podman" "sudo -n docker"; do
  bin=${rt##* }
  command -v $bin >/dev/null 2>&1 || continue
  [ "$bin" = docker ] && docker --version 2>/dev/null | grep -qi podman && continue
  $rt ps --format '{{.Names}}' 2>/dev/null | while read -r n; do
    img=$($rt inspect --format '{{.ImageName}}' "$n" 2>/dev/null || true)
    [ -z "$img" ] || [ "$img" = "<no value>" ] && img=$($rt inspect --format '{{.Config.Image}}' "$n" 2>/dev/null)
    iid=$($rt inspect --format '{{.Image}}' "$n" 2>/dev/null)
    meta=$($rt image inspect --format '{{json .RepoDigests}}|{{.Created}}' "$iid" 2>/dev/null | head -1)
    printf '%s\t%s\t%s\t%s\t%s\n' "$rt" "$n" "$img" "$iid" "$meta"
  done
done
sec k8s
for k in k3s microk8s; do
  command -v $k >/dev/null 2>&1 || continue
  sudo -n "$(command -v $k)" kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.image}{"|"}{.imageID}{";"}{end}{"\n"}{end}' 2>/dev/null
done
sec end
'''


def ssh(ip: str) -> str:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", ip, "bash -s"],
        input=REMOTE, capture_output=True, text=True, timeout=1200)
    if "@@@ os" not in proc.stdout:
        raise RuntimeError((proc.stderr or proc.stdout).strip()[-300:] or f"ssh exit {proc.returncode}")
    return proc.stdout


def sections(out: str) -> dict:
    secs, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@@@ "):
            cur = line[4:].strip()
            secs[cur] = []
        elif cur:
            secs[cur].append(line.rstrip())
    return secs


def parse(ip: str, name: str, out: str) -> dict:
    s = sections(out)
    os_lines = s.get("os", []) + ["", "", ""]
    pm = (s.get("pm") or ["?"])[0]
    host = {"ip": ip, "name": name, "os": os_lines[0], "kernel": os_lines[1], "booted": os_lines[2],
            "pkg_manager": pm, "packages": {}, "updates": [], "update_errors": [l for l in s.get("update_errors", []) if l],
            "security": [], "security_cves": [], "reboot_required": None, "containers": [], "k8s": []}

    for line in s.get("pkgs", []):
        parts = line.split("\t")
        if len(parts) >= 2:
            ver = parts[1][2:] if parts[1].startswith("0:") else parts[1]
            host["packages"][parts[0]] = (host["packages"][parts[0]] + ", " + ver) if parts[0] in host["packages"] else ver

    if pm == "rpm":
        for line in s.get("updates", []):
            if line.startswith(("Obsoleting", "Security:", "Last metadata")):
                if line.startswith("Obsoleting"):
                    break
                continue
            parts = line.split()
            if len(parts) == 3 and "." in parts[0]:
                host["updates"].append({"name": parts[0].rsplit(".", 1)[0], "version": parts[1], "repo": parts[2],
                                        "installed": host["packages"].get(parts[0].rsplit(".", 1)[0], "")})
        for line in s.get("security", []):
            parts = line.split()
            if len(parts) >= 3:
                host["security"].append({"advisory": parts[0], "severity": parts[1].split("/")[0], "package": parts[2]})
        for line in s.get("security_cves", []):
            parts = line.split()
            if len(parts) >= 3:
                host["security_cves"].append({"cve": parts[0], "severity": parts[1].split("/")[0], "package": parts[2]})
    else:
        for line in s.get("updates", []):
            m = re.match(r"(\S+)/(\S+) (\S+) \S+ \[upgradable from: ([^\]]+)\]", line)
            if m:
                host["updates"].append({"name": m.group(1), "version": m.group(3), "repo": m.group(2),
                                        "installed": m.group(4), "security": "-security" in m.group(2)})

    reboot = (s.get("reboot") or ["unknown"])[0].strip()
    host["reboot_required"] = {"1": True, "0": False}.get(reboot)

    for line in s.get("containers", []):
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        digests, created = [], ""
        if len(parts) >= 5 and "|" in parts[4]:
            raw, created = parts[4].split("|", 1)
            try:
                digests = json.loads(raw) or []
            except ValueError:
                pass
        host["containers"].append({"runtime": parts[0].replace("sudo -n ", "") + (" (root)" if "sudo" in parts[0] else ""),
                                   "name": parts[1], "image": parts[2], "image_id": parts[3][:19],
                                   "repo_digests": digests, "created": created[:19]})

    for line in s.get("k8s", []):
        if "\t" not in line:
            continue
        pod, rest = line.split("\t", 1)
        for item in filter(None, rest.split(";")):
            image, _, image_id = item.partition("|")
            host["k8s"].append({"pod": pod, "image": image, "image_id": image_id})
    return host


def load_hosts(path: Path) -> list:
    hosts = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ip, name = line.split()[:2]
            hosts.append((ip, name))
    return hosts


def collect(ip: str, name: str) -> dict:
    started = time.monotonic()
    try:
        host = parse(ip, name, ssh(ip))
    except Exception as e:  # one bad host shouldn't stop the inventory
        host = {"ip": ip, "name": name, "error": f"{type(e).__name__}: {e}"}
    host["collect_seconds"] = round(time.monotonic() - started, 1)
    status = host.get("error") or (f"{len(host['packages'])} pkgs, {len(host['updates'])} updates, "
                                   f"{len(host['security'])} sec advisories, {len(host['containers'])} containers, "
                                   f"{len(host['k8s'])} k8s images")
    print(f"{ip:15} {name:24} {host['collect_seconds']:6.1f}s  {status}", flush=True)
    return host


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=Path, default=BASE / "hosts.conf")
    ap.add_argument("--only", help="comma-separated IPs (writes a partial inventory, not latest.json)")
    args = ap.parse_args()

    hosts = load_hosts(args.hosts)
    if args.only:
        hosts = [h for h in hosts if h[0] in args.only.split(",")]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda h: collect(*h), hosts))

    now = dt.datetime.now()
    inv = {"collected_at": now.isoformat(timespec="seconds"), "collected_ts": time.time(),
           "hosts": {h["ip"]: h for h in results}}
    out = DATA / "inventory"
    out.mkdir(parents=True, exist_ok=True)
    name = f"{now:%Y-%m-%d_%H%M}{'-partial' if args.only else ''}.json"
    (out / name).write_text(json.dumps(inv, indent=1))
    if not args.only:
        (out / "latest.json").write_text(json.dumps(inv, indent=1))
    failed = [h["ip"] for h in results if h.get("error")]
    print(f"saved {out / name}; {len(results) - len(failed)}/{len(results)} hosts ok"
          + (f"; failed: {', '.join(failed)}" if failed else ""), flush=True)


if __name__ == "__main__":
    main()
