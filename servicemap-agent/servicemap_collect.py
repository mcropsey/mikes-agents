#!/usr/bin/env python3
"""Lab service map collector (no LLM). Runs on .98 as mcropsey over the lab SSH key.

Visits every host Grafana shows (Prometheus `up{job="node"}` targets, minus EXCLUDE) and records what runs
there: systemd services (system + user), timers, cron jobs, podman (rootless + root), docker, Kubernetes
workloads (k3s / microk8s), long-running scripts outside any service, listening ports and established
connections to other lab hosts. Command lines are redacted here, before anything is written.

Writes DATA_DIR/servicemap/raw/<date>.json and raw/latest.json for servicemap-agent.

Usage: servicemap_collect.py [--only IP[,IP]] [--hosts-from prometheus|hostsconf]
Stdlib only (runs on the host's python3.9).
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = Path(os.environ.get("LABAGENTS_HOME", "/opt/labagents"))
DATA = BASE / "data"
PROM = os.environ.get("PROM_URL", "http://192.168.1.98:9090")
# Shown in Grafana but reserved by the owner (see hosts.conf): never logged into.
EXCLUDE = set(os.environ.get("SERVICEMAP_EXCLUDE", "192.168.1.77,192.168.1.78").split(","))

# Runs on each host via `ssh host bash -s`. Every block prints an "@@@ <section>" marker first.
REMOTE = r'''
sec(){ echo "@@@ $1"; }
S="sudo -n"
sec os; . /etc/os-release; echo "$PRETTY_NAME"; uname -r; uptime -s; hostname -s; nproc
awk '/MemTotal/{print $2}' /proc/meminfo

# --- systemd (system) ---
timers=$($S systemctl list-units --type=timer --all --no-legend --plain --no-pager 2>/dev/null | awk '$2=="loaded"{print $1}')
sec timers
[ -n "$timers" ] && $S systemctl show --no-pager -p Id,Description,Unit,TimersCalendar,TimersMonotonic,LastTriggerUSec,NextElapseUSecRealtime,ActiveState,UnitFileState $timers
timer_units=$([ -n "$timers" ] && $S systemctl show --no-pager -p Unit --value $timers | sort -u)
svcs=$( ( $S systemctl list-units --type=service --state=running,failed,activating --no-legend --plain --no-pager | awk '{print $1}'; echo "$timer_units" ) | grep . | sort -u)
sec services
$S systemctl show --no-pager -p Id,Description,FragmentPath,User,ExecStart,ActiveState,SubState,UnitFileState,Type,ControlGroup,Result $svcs
# --- systemd (user managers: lingering users + anyone with a running user@ unit, uid >= 1000) ---
for u in $( (ls /var/lib/systemd/linger 2>/dev/null; loginctl list-users --no-legend 2>/dev/null | awk '{print $2}') | sort -u); do
  uid=$(id -u "$u" 2>/dev/null) || continue; [ "$uid" -ge 1000 ] || continue
  sec "userunits $u"
  $S systemctl --user -M "$u@" list-units --type=service,timer --state=running,failed,active --no-legend --plain --no-pager 2>/dev/null
done

# --- containers ---
if command -v podman >/dev/null 2>&1; then
  sec "podman root"; $S podman ps -a --format json 2>/dev/null
  for u in $( (id -un; ps -eo user=,comm= | awk '$2=="conmon"||$2=="podman"||$2=="catatonit"{print $1}'; ls /var/lib/systemd/linger 2>/dev/null) | sort -u); do
    [ "$u" = root ] && continue
    uid=$(id -u "$u" 2>/dev/null) || continue
    sec "podman user $u"
    if [ "$u" = "$(id -un)" ]; then podman ps -a --format json 2>/dev/null
    else $S -u "$u" env XDG_RUNTIME_DIR=/run/user/$uid podman ps -a --format json 2>/dev/null; fi
  done
fi
if command -v docker >/dev/null 2>&1 && ! docker --version 2>/dev/null | grep -qi podman; then
  sec docker; $S docker ps -a --no-trunc --format '{{json .}}' 2>/dev/null
fi

# --- kubernetes ---
for k in k3s microk8s; do
  command -v $k >/dev/null 2>&1 || continue
  K="$S $(command -v $k) kubectl"
  sec "k8s $k"
  $K get ns kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null; echo
  $K get nodes,deploy,sts,ds,svc,cronjob,pods -A -o json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin); out=[]
for i in d["items"]:
    m,s,st=i["metadata"],i.get("spec",{}),i.get("status",{})
    o={"kind":i["kind"],"ns":m.get("namespace",""),"name":m["name"],"labels":m.get("labels",{})}
    if i["kind"]=="Node":
        o["ip"]=next((a["address"] for a in st.get("addresses",[]) if a["type"]=="InternalIP"),"")
        o["version"]=st.get("nodeInfo",{}).get("kubeletVersion","")
    elif i["kind"]=="Pod":
        o.update(node=s.get("nodeName",""),phase=st.get("phase",""),
                 owner=[r["kind"]+"/"+r["name"] for r in m.get("ownerReferences",[])],
                 images=[c["image"] for c in s.get("containers",[])],
                 ready=sum(1 for c in st.get("containerStatuses",[]) if c.get("ready")),
                 restarts=sum(c.get("restartCount",0) for c in st.get("containerStatuses",[])))
    elif i["kind"]=="Service":
        o.update(type=s.get("type",""),ports=[str(p.get("nodePort") or p.get("port"))+"/"+p.get("protocol","TCP") for p in s.get("ports",[])])
    elif i["kind"]=="CronJob":
        o.update(schedule=s.get("schedule",""),images=[c["image"] for c in s["jobTemplate"]["spec"]["template"]["spec"]["containers"]])
    else:
        tpl=s.get("template",{}).get("spec",{})
        o.update(replicas=s.get("replicas",st.get("desiredNumberScheduled")),ready=st.get("readyReplicas",st.get("numberReady",0)),
                 images=[c["image"] for c in tpl.get("containers",[])])
    out.append(o)
print(json.dumps(out))'
done

# --- cron ---
sec cron
for f in /etc/crontab /etc/cron.d/*; do [ -f "$f" ] && $S awk -v f="$f" 'NF && $1 !~ /^#/ {print "system\t" f "\t" $0}' "$f"; done
for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do [ -f "$f" ] && $S awk -v u="$(basename $f)" 'NF && $1 !~ /^#/ {print "user\t" u "\t" $0}' "$f"; done
for d in hourly daily weekly monthly; do for f in /etc/cron.$d/*; do [ -f "$f" ] && printf 'dir\t%s\t@%s %s\n' "$d" "$d" "$f"; done; done

# --- network (each socket tagged with the owning process's cgroup -> service/container) ---
cgof(){ [ -n "$1" ] && $S cat /proc/$1/cgroup 2>/dev/null | tail -1 | cut -d: -f3; }
sec listen
$S ss -tlnpH 2>/dev/null | while read -r line; do
  printf '%s\t%s\n' "$line" "$(cgof "$(grep -oE 'pid=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)")"; done
sec conns
$S ss -tnpH state established 2>/dev/null | while read -r line; do
  printf '%s\t%s\n' "$line" "$(cgof "$(grep -oE 'pid=[0-9]+' <<<"$line" | head -1 | cut -d= -f2)")"; done
# lab endpoints each service is configured to call (host:port only, from Environment= and env files)
sec endpoints
for u in $svcs; do
  files=$( ($S systemctl show -p EnvironmentFiles --value "$u" | awk '{print $1}' | sed 's/^-//';
            $S systemctl show -p ExecStart --value "$u" | grep -oE -- '--env-file[= ][^ ;]+' | sed -E 's/--env-file[= ]//') | grep . )
  urls=$( ($S systemctl show -p Environment --value "$u"; for f in $files; do $S cat "$f" 2>/dev/null; done) |
          grep -oE 'https?://[A-Za-z0-9.-]+:[0-9]+' | sed -E 's#https?://##' | sort -u | tr '\n' ' ')
  [ -n "$urls" ] && echo "$u $urls"
done

# --- long-running interpreters/scripts (attributed to their cgroup) ---
sec procs
$S ps -eo pid=,user=,etimes=,comm=,args= | awk '$3>300 && $4 ~ /^(python|node|java|bun|deno|ruby|perl|php|uvicorn|gunicorn|claude|opencode|ollama|bash|sh|npm|npx|uv|go|dotnet)/' |
while read -r pid user et comm args; do
  cg=$($S cat /proc/$pid/cgroup 2>/dev/null | tail -1 | cut -d: -f3); cwd=$($S readlink /proc/$pid/cwd 2>/dev/null)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$user" "$et" "$comm" "$cg" "$cwd" "${args:0:400}"
done
sec end
'''

# ---------- redaction: nothing secret leaves this function ----------
_SECRET_PATTERNS = [
    (re.compile(r"(?i)\b([\w.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|apikey|auth|credential|private[_-]?key)[\w.-]*)(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1\2***"),
    (re.compile(r"(?i)(--?(?:p|pw|pass|password|token|key|secret)(?:=|\s+))(\S+)"), r"\1***"),
    (re.compile(r"(?i)(bearer\s+)\S+"), r"\1***"),
    (re.compile(r"(\w+://)[^/\s:@]+:[^/\s@]+@"), r"\1***:***@"),
    (re.compile(r"\b(sk|pk|ghp|gho|ghs|github_pat|xox[abp]|glpat|AKIA)[-_A-Za-z0-9]{8,}"), "***"),
    (re.compile(r"\b[A-Za-z0-9+_\-]{32,}={0,2}(?![\w/])"), "***"),
]


def redact(text: str) -> str:
    for pat, rep in _SECRET_PATTERNS:
        text = pat.sub(rep, text)
    return text


# ---------- parsing ----------

def sections(out: str) -> dict:
    secs, cur = {}, None
    for line in out.splitlines():
        if line.startswith("@@@ "):
            cur = line[4:].strip()
            secs.setdefault(cur, [])
        elif cur:
            secs[cur].append(line.rstrip("\n"))
    return secs


def show_blocks(lines: list) -> list:
    """`systemctl show` output: blank-line separated KEY=VALUE blocks."""
    blocks, cur = [], {}
    for line in lines + [""]:
        if not line.strip():
            if cur:
                blocks.append(cur)
            cur = {}
        elif "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    return blocks


def exec_of(execstart: str) -> tuple:
    """ExecStart={ path=/usr/bin/x ; argv[]=/usr/bin/x a b ; ... } -> (program, script-or-subcommand)."""
    m = re.search(r"argv\[\]=([^;]*)", execstart or "")
    argv = (m.group(1).split() if m else (execstart or "").split())
    if not argv:
        return "", ""
    prog = argv[0]
    rest = [a for a in argv[1:] if not a.startswith("-")]
    detail = ""
    if os.path.basename(prog).startswith(("python", "node", "bash", "sh", "perl", "ruby", "java", "bun", "deno")):
        detail = next((a for a in rest if "/" in a or a.endswith((".py", ".js", ".sh", ".jar"))), "")
    elif os.path.basename(prog) in ("podman", "docker") and rest:
        img = next((a for a in rest[1:] if ("/" in a or ":" in a) and not a.startswith("/")), "")
        detail = f"{rest[0]} {img}".strip()
    elif rest:
        detail = rest[0]
    return prog, redact(detail)[:160]


def parse_containers(engine: str, owner: str, lines: list) -> list:
    raw = "\n".join(lines).strip()
    if not raw:
        return []
    items = []
    if raw.startswith("["):
        try:
            items = json.loads(raw)
        except ValueError:
            return []
    else:  # docker: one JSON object per line
        for line in raw.splitlines():
            try:
                items.append(json.loads(line))
            except ValueError:
                pass
    out = []
    for c in items:
        if engine == "podman":
            labels = c.get("Labels") or {}
            if c.get("IsInfra"):
                continue
            ports = sorted({f"{p.get('host_port')}->{p.get('container_port')}/{p.get('protocol', 'tcp')}"
                            for p in (c.get("Ports") or []) if p.get("host_port")})
            out.append({"engine": "podman", "rootful": owner == "root", "owner": owner, "id": c.get("Id", "")[:12],
                        "name": (c.get("Names") or ["?"])[0], "image": c.get("Image", ""),
                        "state": c.get("State", ""), "status": c.get("Status", ""), "ports": ports,
                        "pod": c.get("PodName", ""),
                        "systemd_unit": labels.get("PODMAN_SYSTEMD_UNIT", ""),
                        "compose": labels.get("com.docker.compose.project", labels.get("io.podman.compose.project", "")),
                        "created": str(c.get("CreatedAt", ""))[:19]})
        else:
            labels = dict(kv.split("=", 1) for kv in (c.get("Labels") or "").split(",") if "=" in kv)
            ports = sorted({p.strip() for p in (c.get("Ports") or "").split(",") if "->" in p})
            out.append({"engine": "docker", "rootful": True, "owner": "root", "id": c.get("ID", "")[:12],
                        "name": c.get("Names", "?"),
                        "image": c.get("Image", ""), "state": c.get("State", ""), "status": c.get("Status", ""),
                        "ports": ports, "pod": "", "systemd_unit": "",
                        "compose": labels.get("com.docker.compose.project", ""),
                        "created": str(c.get("CreatedAt", ""))[:19]})
    return out


def parse(ip: str, name: str, out: str) -> dict:
    s = sections(out)
    o = s.get("os", []) + [""] * 6
    host = {"ip": ip, "name": name, "os": o[0], "kernel": o[1], "booted": o[2], "hostname": o[3],
            "cpus": int(o[4]) if o[4].isdigit() else None,
            "mem_gb": round(int(o[5]) / 1048576, 1) if o[5].isdigit() else None,
            "services": [], "timers": [], "user_units": [], "containers": [], "k8s": [], "cron": [],
            "listen": [], "conns": [], "endpoints": {}, "procs": []}

    for b in show_blocks(s.get("timers", [])):
        cal = re.findall(r"OnCalendar=([^;]+?)\s*;", b.get("TimersCalendar", ""))
        mono = re.findall(r"\{ (\w+) ; next_elapse", b.get("TimersMonotonic", ""))
        host["timers"].append({"unit": b.get("Id", ""), "activates": b.get("Unit", ""),
                               "description": b.get("Description", ""),
                               "schedule": ", ".join(cal) or ", ".join(mono),
                               "last": b.get("LastTriggerUSec", ""), "next": b.get("NextElapseUSecRealtime", ""),
                               "enabled": b.get("UnitFileState", ""), "active": b.get("ActiveState", "")})

    for b in show_blocks(s.get("services", [])):
        if not b.get("Id"):
            continue
        prog, detail = exec_of(b.get("ExecStart", ""))
        path = b.get("FragmentPath", "")
        origin = ("local" if path.startswith(("/etc/systemd/system", "/etc/systemd/user", "/run/systemd/generator"))
                  and not os.path.islink(path) else "vendor") if path else "transient"
        host["services"].append({"unit": b["Id"], "description": b.get("Description", ""), "path": path,
                                 "origin": origin, "user": b.get("User", "") or "root", "exec": prog,
                                 "detail": detail, "type": b.get("Type", ""), "state": b.get("ActiveState", ""),
                                 "sub": b.get("SubState", ""), "enabled": b.get("UnitFileState", ""),
                                 "result": b.get("Result", ""), "cgroup": b.get("ControlGroup", "")})

    for sec_name, lines in s.items():
        if sec_name.startswith("userunits "):
            user = sec_name.split(" ", 1)[1]
            for line in lines:
                parts = line.split(None, 4)
                if len(parts) >= 4 and parts[1] == "loaded":
                    host["user_units"].append({"user": user, "unit": parts[0], "state": parts[2], "sub": parts[3],
                                               "description": parts[4] if len(parts) > 4 else ""})
        elif sec_name == "podman root":
            host["containers"] += parse_containers("podman", "root", lines)
        elif sec_name.startswith("podman user "):
            host["containers"] += parse_containers("podman", sec_name.split()[-1], lines)
        elif sec_name == "docker":
            host["containers"] += parse_containers("docker", "root", lines)
        elif sec_name.startswith("k8s "):
            flavor = sec_name.split()[1]
            if len(lines) >= 2 and lines[1].startswith("["):
                host["k8s"].append({"flavor": flavor, "cluster_id": lines[0].strip(), "objects": json.loads(lines[1])})

    for line in s.get("cron", []):
        kind, src, entry = (line.split("\t", 2) + ["", ""])[:3]
        if re.match(r"^\s*[A-Z_]+=", entry):  # env assignment, e.g. MAILTO=
            continue
        parts = entry.split()
        if entry.startswith("@"):
            sched, rest = parts[0], parts[1:]
        else:
            sched, rest = " ".join(parts[:5]), parts[5:]
        run_as = ""
        if kind == "system" and rest:
            run_as, rest = rest[0], rest[1:]
        elif kind == "user":
            run_as = src
        host["cron"].append({"source": kind if kind != "system" else src, "schedule": sched,
                             "user": run_as, "command": redact(" ".join(rest))[:200]})

    for line in s.get("listen", []):
        sock, _, cg = line.partition("\t")
        p = sock.split()
        if len(p) < 4:
            continue
        addr, _, port = p[3].rpartition(":")
        host["listen"].append({"addr": addr.strip("[]"), "port": int(port) if port.isdigit() else port,
                               "process": ",".join(sorted(set(re.findall(r'"([^"]+)"', sock)))), "cgroup": cg})

    seen = set()
    for line in s.get("conns", []):
        sock, _, cg = line.partition("\t")
        p = sock.split()
        if len(p) < 4:
            continue
        lport = p[2].rpartition(":")[2]
        rip, _, rport = p[3].rpartition(":")
        rip = rip.strip("[]").replace("::ffff:", "")
        proc = (re.findall(r'"([^"]+)"', sock) or ["?"])[0]
        key = (lport, rip, rport, proc, cg)
        if rip.startswith("127.") or rip == "::1" or key in seen:
            continue
        seen.add(key)
        host["conns"].append({"local_port": int(lport) if lport.isdigit() else lport, "peer": rip,
                              "peer_port": int(rport) if rport.isdigit() else rport, "process": proc, "cgroup": cg})

    host["endpoints"] = {}
    for line in s.get("endpoints", []):
        parts = line.split()
        if len(parts) >= 2:
            host["endpoints"][parts[0]] = parts[1:]

    for line in s.get("procs", []):
        p = line.split("\t", 6)
        if len(p) < 7:
            continue
        pid, user, etimes, comm, cg, cwd, args = p
        argv = args.split()
        if "<defunct>" in args:
            continue
        if comm in ("bash", "sh") and not any(a.endswith(".sh") or ("/" in a and not a.startswith("-"))
                                              for a in argv[1:]):
            continue  # interactive shell, not a script
        if "-c" in argv[1:3]:
            script = "(inline " + comm + " -c)"
        else:
            script = next((a for a in argv[1:] if not a.startswith("-") and ("/" in a or "." in a)), "")
        if script and not script.startswith(("/", "(")) and cwd not in ("", "/"):
            script = cwd.rstrip("/") + "/" + script
        script = re.sub(r"^/home/[^/]+/", "~/", script)
        host["procs"].append({"pid": int(pid), "user": user, "age_h": round(int(etimes) / 3600, 1), "comm": comm,
                              "cgroup": cg, "script": redact(script)[:160], "args": redact(args)[:300]})
    return host


# ---------- host list ----------

def hostsconf_names() -> dict:
    names = {}
    path = BASE / "hosts.conf"
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                ip, name = line.split()[:2]
                names[ip] = name
    return names


def grafana_hosts() -> list:
    """Hosts as Grafana sees them: every Prometheus node_exporter target."""
    url = PROM + "/api/v1/query?query=" + urllib.request.quote('up{job="node"}')
    with urllib.request.urlopen(url, timeout=20) as r:
        res = json.loads(r.read())["data"]["result"]
    return sorted({m["metric"]["instance"].rsplit(":", 1)[0] for m in res},
                  key=lambda ip: tuple(int(x) for x in ip.split(".")))


def ssh(ip: str) -> str:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", ip, "bash -s"],
        input=REMOTE, capture_output=True, text=True, timeout=600)
    if "@@@ os" not in proc.stdout:
        raise RuntimeError((proc.stderr or proc.stdout).strip()[-300:] or f"ssh exit {proc.returncode}")
    return proc.stdout


def collect(ip: str, name: str) -> dict:
    started = time.monotonic()
    try:
        host = parse(ip, name, ssh(ip))
    except Exception as e:  # one bad host shouldn't stop the map
        host = {"ip": ip, "name": name, "error": f"{type(e).__name__}: {e}"}
    host["collect_seconds"] = round(time.monotonic() - started, 1)
    status = host.get("error") or (
        f"{len(host['services'])} services, {len(host['timers'])} timers, {len(host['containers'])} containers, "
        f"{sum(len(k['objects']) for k in host['k8s'])} k8s objects, {len(host['cron'])} cron, "
        f"{len(host['procs'])} procs")
    print(f"{ip:15} {name:20} {host['collect_seconds']:5.1f}s  {status}", flush=True)
    return host


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated IPs (writes a partial snapshot, not latest.json)")
    ap.add_argument("--hosts-from", choices=["prometheus", "hostsconf"], default="prometheus")
    args = ap.parse_args()

    names = hostsconf_names()
    source = args.hosts_from
    if source == "prometheus":
        try:
            ips = grafana_hosts()
        except Exception as e:
            print(f"prometheus unavailable ({e}); falling back to hosts.conf", flush=True)
            ips, source = list(names), "hostsconf"
    else:
        ips = list(names)
    excluded = [ip for ip in ips if ip in EXCLUDE]
    ips = [ip for ip in ips if ip not in EXCLUDE]
    if args.only:
        ips = [ip for ip in ips if ip in args.only.split(",")]

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda ip: collect(ip, names.get(ip, ip)), ips))
    for h in results:  # names for hosts that aren't in hosts.conf come from the host itself
        if h["name"] == h["ip"] and h.get("hostname"):
            h["name"] = h["hostname"]

    now = dt.datetime.now()
    snap = {"collected_at": now.isoformat(timespec="seconds"), "collected_ts": time.time(),
            "host_source": source, "excluded": excluded, "hosts": {h["ip"]: h for h in results}}
    out = DATA / "servicemap" / "raw"
    out.mkdir(parents=True, exist_ok=True)
    fname = f"{now:%Y-%m-%d_%H%M}{'-partial' if args.only else ''}.json"
    (out / fname).write_text(json.dumps(snap, indent=1))
    if not args.only:
        (out / "latest.json").write_text(json.dumps(snap, indent=1))
    failed = [h["ip"] for h in results if h.get("error")]
    print(f"saved {out / fname}; {len(results) - len(failed)}/{len(results)} hosts ok"
          + (f"; failed: {', '.join(failed)}" if failed else "")
          + (f"; excluded (reserved): {', '.join(excluded)}" if excluded else ""), flush=True)
    if failed and len(failed) == len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
