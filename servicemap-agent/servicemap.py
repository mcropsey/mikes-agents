"""servicemap-agent: a daily map of everything running in the lab.

Reads the snapshot servicemap_collect.py takes over SSH (systemd, timers, cron, podman, docker, Kubernetes,
ad-hoc scripts, sockets, configured endpoints), turns it into components and dependency edges, asks the
model to categorise each component and say what it is for (answers are cached, so only new components
cost GPU time), diffs against the previous map, and renders:

  DATA/servicemap/site/index.html       the page Grafana embeds (served on .98:9440)
  DATA/servicemap/site/README.md        the same map for GitHub (mermaid + tables)
  DATA/servicemap/site/servicemap.json  the published model (redacted, no command lines)

Usage: python -m labagents.servicemap [--no-llm] [--no-email] [--to ADDR] [--reclassify]
"""
import argparse
import datetime as dt
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

from .common import DATA, LAB_HOSTS, MAIL_TO, Agent, e, log, save_report, send_mail

SM = DATA / "servicemap"
SITE = SM / "site"
CACHE = SM / "classify-cache.json"
EXTRA_EDGES = SM / "extra-edges.conf"
PAGE_URL = "http://192.168.1.98:9440/"
REPO_URL = "https://github.com/mcropsey/cropsey-lab/tree/main/service-map"

# Category order = the validated categorical palette's slot order (see dataviz palette check in the README).
CATS = [
    ("ai-agent", "AI agents", "Programs that call an LLM, AI coding sessions, AI traffic simulators"),
    ("ai-platform", "AI platform", "LLM gateway, model servers, MCP servers, vector DB, AI search"),
    ("observability", "Observability", "Metrics, logs, alerting, dashboards, exporters"),
    ("security", "API security", "Sensors and security tooling"),
    ("network", "Network & ingress", "Gateways, proxies, ingress, tunnels, DNS"),
    ("ops", "Ops & CI", "CI/CD, backups, maintenance jobs, mirrors, file shares, admin scripts"),
    ("platform", "Platform & data", "Container runtimes, Kubernetes, databases"),
    ("app", "Lab target apps", "Intentionally vulnerable demo apps and their parts"),
]
CAT_KEYS = [c[0] for c in CATS]
CAT_LABEL = {c[0]: c[1] for c in CATS}
RUNTIME_LABEL = {"systemd": "systemd", "timer": "timer", "user-unit": "user unit", "cron": "cron",
                 "podman": "podman", "podman-root": "root podman", "docker": "docker", "k8s": "k8s",
                 "process": "process", "external": "external"}

# ---------- baseline (OS noise) ----------
BASE_UNIT = re.compile(
    r"^(systemd-.*|dbus.*|NetworkManager.*|ModemManager|accounts-daemon|atd|auditd|avahi-daemon|bluetooth|chronyd|"
    r"colord|cron|crond|anacron|cups.*|e2scrub.*|firewalld|fstrim|fwupd.*|gdm|lightdm|(serial-)?getty@.*|gssproxy|"
    r"hyperv.*|irqbalance|libstoragemgmt|logrotate|man-db|mcelog|[mp]locate-updatedb|motd-news|netplan-.*|polkit|"
    r"raid-check|rsyslog|rtkit-daemon|snapd.*|sshd?|sssd.*|switcheroo-control|sysstat.*|atop.*|tuned.*|udisks2|"
    r"unattended-upgrades|update-notifier-.*|upower|user@\d+|user-runtime-dir@.*|wpa_supplicant|apport.*|"
    r"apt-daily.*|dpkg-db-backup|dnf-makecache|ua-timer|vmtoolsd|vgauthd|qemu-guest-agent|kdump|rngd|smartd|"
    r"power-profiles-daemon|thermald|packagekit|rpcbind|rpc-statd.*|nfs-idmapd|nfsdcld|run-.*|"
    r"[0-9a-f]{64}-[0-9a-f]+)(\.service|\.timer)?$")
BASE_USER_UNIT = re.compile(r"^(dbus.*|dconf|filter-chain|gnome-.*|gvfs-.*|pipewire.*|wireplumber|xdg-.*|obex|"
                            r"grub-boot-success|systemd-.*|launchpadlib-.*|at-spi.*|evolution-.*|tracker-.*|"
                            r"evolution.*|gcr-.*|ibus.*|org\.gnome\..*)(\.service|\.timer)?$")
BASE_CRON = re.compile(r"run-parts|e2scrub|debian-sa1|anacron|atop|sysstat|apt-compat|/dpkg$|logrotate|man-db|"
                       r"[mp]locate|apport|cron\.daily/apache2|0hourly|/dpkg\b")
BASE_K8S = re.compile(r"^(coredns|metrics-server|local-path-provisioner|hostpath-provisioner|calico-.*)$")
DESKTOP_PROC = re.compile(r"^(goa-|gsd-|gnome-|ibus|tracker|evolution|at-spi|xdg-|npm$|npx$)")

# ---------- rule-based fallback (also given to the model as a hint) ----------
RULES = [
    (r"jenkins", "ops", False),
    (r"secnews|labwatch|cvewatch|patchwatch|servicemap|ai-sim|ai_sim|generate_traffic|opencode|claude|"
     r"mcp.heartbeat|crapi_sweep|mcp-sweep", "ai-agent", True),
    (r"chatbot", "app", True),
    (r"litellm|ollama|lm.?studio|vllm|chroma|searxng|mcp", "ai-platform", True),
    (r"noname|sensor", "security", False),
    (r"prometheus|grafana|loki|alloy|alertmanager|cadvisor|exporter|glances|vnotes|vulnnotes", "observability", False),
    (r"kong|nginx|ingress|cloudflared|traefik|httpd|apache|dnsmasq|twingate|haproxy|envoy", "network", False),
    (r"crapi|juice|vampi|dvga|mailhog|dealership|webgoat|dvwa", "app", False),
    (r"jenkins|dind|backup|reboot|inventory|nfs|mirror|cockpit", "ops", False),
    (r"k3s|microk8s|kube|calico|coredns|containerd|docker|podman|postgres|mongo|redis|mysql|mariadb|"
     r"metrics-server|provisioner", "platform", False),
]


def rule_guess(c: dict) -> tuple:
    text = " ".join(str(c.get(k, "")) for k in ("name", "image", "detail", "description", "group")).lower()
    for pat, cat, ai in RULES:
        if re.search(pat, text):
            return cat, ai
    return "ops", False


# ---------- model ----------

def cgroup_key(cg: str):
    m = re.search(r"(?:libpod-|docker-|/docker/|libpod/)([0-9a-f]{12})", cg or "")
    if m:
        return ("ctr", m.group(1))
    if "kubepods" in (cg or "") or "cri-containerd" in (cg or ""):
        return ("k8s", "")
    m = re.search(r"user@\d+\.service/(?:.*/)?([^/]+\.service)", cg or "")
    if m:
        return ("user", m.group(1))
    m = re.search(r"session-\d+\.scope", cg or "")
    if m:
        return ("session", "")
    units = re.findall(r"([^/]+\.service)", cg or "")
    return ("unit", units[-1]) if units else (None, None)


def host_port(mapping: str):
    m = re.match(r"(?:.*:)?(\d+)->", mapping)
    return int(m.group(1)) if m else None


def build(snap: dict) -> dict:
    comps, hosts, k8s_clusters = {}, {}, {}
    by_cg = {}           # (ip, key-tuple) -> comp id
    port_map = {}        # (ip, port) -> comp id
    unit_alias = {}      # (ip, unit) -> comp id (podman-wrapper units -> their container)
    adhoc_by_comm = {}   # (ip, comm) -> comp id
    names = {ip: h["name"] for ip, h in snap["hosts"].items()}

    def add(c):
        c.setdefault("hosts", [c["host"]] if c.get("host") else [])
        c.setdefault("baseline", False)
        comps[c["id"]] = c
        return c["id"]

    for ip, h in snap["hosts"].items():
        hosts[ip] = {"ip": ip, "name": h["name"], "os": h.get("os", ""), "kernel": h.get("kernel", ""),
                     "booted": h.get("booted", ""), "cpus": h.get("cpus"), "mem_gb": h.get("mem_gb"),
                     "error": h.get("error", ""), "listen": []}
        if h.get("error"):
            continue
        timer_for = {t["activates"]: t for t in h["timers"]}
        wrapped = defaultdict(list)
        for c in h["containers"]:
            if c["systemd_unit"]:
                wrapped[c["systemd_unit"]].append(c)

        for c in h["containers"]:
            kind = "docker" if c["engine"] == "docker" else ("podman-root" if c["rootful"] else "podman")
            cid = add({"id": f"{ip}/{kind}/{c['owner']}/{c['name']}", "host": ip, "kind": kind, "name": c["name"],
                       "image": c["image"], "state": c["state"], "status": c["status"], "ports": c["ports"],
                       "user": c["owner"], "group": c["compose"] or c["pod"] or "",
                       "unit": c["systemd_unit"], "detail": c["image"]})
            if c.get("id"):
                by_cg[(ip, ("ctr", c["id"]))] = cid
            for p in c["ports"]:
                hp = host_port(p)
                if hp:
                    port_map[(ip, hp)] = cid
            if c["systemd_unit"]:
                unit_alias.setdefault((ip, c["systemd_unit"]), cid)

        for s in h["services"]:
            unit = s["unit"]
            if unit in wrapped:  # shown as its container(s)
                continue
            t = timer_for.get(unit)
            base = bool(BASE_UNIT.match(unit)) and s["origin"] != "local" or bool(re.match(r"^[0-9a-f]{64}-", unit))
            cid = add({"id": f"{ip}/unit/{unit}", "host": ip, "kind": "timer" if t else "systemd",
                       "name": re.sub(r"\.service$", "", unit), "unit": unit, "description": s["description"],
                       "detail": " ".join(x for x in (s["exec"], s["detail"]) if x), "user": s["user"],
                       "state": s["sub"] if s["state"] == "active" else s["state"], "result": s["result"],
                       "schedule": t["schedule"] if t else "", "origin": s["origin"], "baseline": base,
                       "endpoints": h.get("endpoints", {}).get(unit, [])})
            by_cg[(ip, ("unit", unit))] = cid

        for u in h["user_units"]:
            if not u["unit"].endswith(".service"):
                continue
            cid = add({"id": f"{ip}/user/{u['user']}/{u['unit']}", "host": ip, "kind": "user-unit",
                       "name": re.sub(r"\.service$", "", u["unit"]), "unit": u["unit"], "user": u["user"],
                       "description": u["description"], "state": u["sub"],
                       "baseline": bool(BASE_USER_UNIT.match(u["unit"]))})
            by_cg[(ip, ("user", u["unit"]))] = cid

        for cr in h["cron"]:
            cmd = cr["command"]
            script = next((w for w in cmd.split() if "/" in w and not w.startswith(("/dev/", "/run/", "/usr/sbin/anacron"))), "")
            name = Path(script).name if script else (cmd.split() or ["cron"])[0]
            add({"id": f"{ip}/cron/{hashlib.sha1((cr['schedule'] + cmd).encode()).hexdigest()[:10]}", "host": ip,
                 "kind": "cron", "name": name, "schedule": cr["schedule"], "user": cr["user"],
                 "detail": script, "description": f"cron ({cr['source']})", "state": "scheduled",
                 "baseline": bool(BASE_CRON.search(cmd + " " + cr["source"]))})

        seen = {}
        for p in h["procs"]:
            key = cgroup_key(p["cgroup"])
            if key[0] != "session" and "/app.slice/" not in p["cgroup"] and "tmux" not in p["cgroup"]:
                continue  # belongs to a service/container already on the map
            if DESKTOP_PROC.match(p["comm"]) or (p["comm"] in ("sh", "bash") and p["script"].startswith("(inline")):
                continue
            label = Path(p["script"]).name if p["script"] and not p["script"].startswith("(") else p["comm"]
            pid_ = f"{ip}/proc/{p['user']}/{label}"
            if pid_ in seen:
                comps[pid_]["count"] += 1
                continue
            seen[pid_] = True
            add({"id": pid_, "host": ip, "kind": "process", "name": label, "user": p["user"],
                 "detail": p["script"] or p["comm"], "state": "running", "count": 1,
                 "description": f"long-running {p['comm']} outside any service (up {p['age_h']}h)"})
            adhoc_by_comm[(ip, p["comm"])] = pid_

        for lst in h["listen"]:
            key = cgroup_key(lst["cgroup"])
            cid = by_cg.get((ip, key))
            if cid and (ip, lst["port"]) not in port_map:
                port_map[(ip, lst["port"])] = cid
            hosts[ip]["listen"].append({"port": lst["port"], "addr": lst["addr"], "process": lst["process"],
                                        "component": comps[cid]["name"] if cid else ""})
        hosts[ip]["listen"] = sorted({(x["port"], x["process"], x["component"]): x for x in hosts[ip]["listen"]
                                      if isinstance(x["port"], int)}.values(), key=lambda x: x["port"])

        for k in h["k8s"]:
            cl = k8s_clusters.setdefault(k["cluster_id"], {"id": k["cluster_id"], "flavor": k["flavor"],
                                                           "seen_on": [], "objects": k["objects"]})
            cl["seen_on"].append(ip)

    # Kubernetes: one set of workloads per cluster, placed on the hosts their pods run on.
    for cl in k8s_clusters.values():
        objs = cl["objects"]
        node_ip = {o["name"]: o.get("ip", "") for o in objs if o["kind"] == "Node"}
        cl["nodes"] = [{"name": n, "ip": i, "host": names.get(i, n)} for n, i in node_ip.items()]
        short = f"{cl['flavor']}-{cl['id'][:6]}"
        cl["name"] = f"{cl['flavor']} ({', '.join(sorted(names.get(i, n) for n, i in node_ip.items()))})"
        pods_by_owner = defaultdict(list)
        for o in objs:
            if o["kind"] == "Pod":
                for ow in o.get("owner") or [f"Pod/{o['name']}"]:
                    kind, name = ow.split("/", 1)
                    if kind == "ReplicaSet":
                        kind, name = "Deployment", name.rsplit("-", 1)[0]
                    elif kind == "Job":
                        kind, name = "CronJob", name.rsplit("-", 1)[0]
                    pods_by_owner[(o["ns"], kind, name)].append(o)
        cl["workloads"] = []
        for o in objs:
            if o["kind"] not in ("Deployment", "StatefulSet", "DaemonSet", "CronJob"):
                continue
            pods = pods_by_owner.get((o["ns"], o["kind"], o["name"]), [])
            ips = sorted({node_ip.get(p["node"], "") for p in pods if p.get("node")} - {""})
            cid = add({"id": f"k8s/{short}/{o['ns']}/{o['kind']}/{o['name']}", "host": ips[0] if ips else cl["seen_on"][0],
                       "hosts": ips or cl["seen_on"][:1], "kind": "k8s", "name": o["name"], "namespace": o["ns"],
                       "k8s_kind": o["kind"], "cluster": cl["name"], "image": ", ".join(o.get("images", [])),
                       "detail": f"{o['kind']} in {o['ns']}", "schedule": o.get("schedule", ""),
                       "replicas": o.get("replicas"), "ready": o.get("ready"),
                       "state": "running" if o["kind"] == "CronJob" or (o.get("ready") or 0) >= (o.get("replicas") or 0) and o.get("replicas") else "degraded",
                       "restarts": sum(p.get("restarts", 0) for p in pods),
                       "baseline": o["ns"] == "kube-system" or bool(BASE_K8S.match(o["name"]))})
            cl["workloads"].append(cid)
        for o in objs:  # NodePorts on every node -> the workload with the same name
            if o["kind"] == "Service" and o.get("type") in ("NodePort", "LoadBalancer"):
                target = next((w for w in cl["workloads"] if comps[w]["name"] == o["name"] and comps[w]["namespace"] == o["ns"]), None)
                target = target or next((w for w in cl["workloads"] if comps[w]["namespace"] == o["ns"]
                                         and not comps[w]["baseline"]), None)
                for p in o.get("ports", []):
                    port = int(p.split("/")[0]) if p.split("/")[0].isdigit() else None
                    if target and port:
                        comps[target].setdefault("ports", []).append(p)
                        for n in cl["nodes"]:
                            port_map.setdefault((n["ip"], port), target)
        del cl["objects"]

    edges = build_edges(snap, comps, by_cg, port_map, unit_alias, adhoc_by_comm, names)
    for c in comps.values():
        c.pop("endpoints", None)
    return {"hosts": hosts, "components": comps, "edges": edges, "clusters": list(k8s_clusters.values())}


def build_edges(snap, comps, by_cg, port_map, unit_alias, adhoc_by_comm, names) -> list:
    lab_ips = set(snap["hosts"])
    name_ip = {v["name"]: k for k, v in snap["hosts"].items()}
    agg = {}

    excluded = set(snap.get("excluded", []))

    def ext(ip, port):
        eid = f"ext/{ip}:{port}"
        if eid not in comps:
            label = {"192.168.1.194:1234": "LM Studio (qwen3.8-27b, RTX 5090)"}.get(
                f"{ip}:{port}", f"{ip}:{port}" + (" (reserved, not mapped)" if ip in excluded else ""))
            comps[eid] = {"id": eid, "host": "", "hosts": [], "kind": "external", "name": label,
                          "detail": f"{ip}:{port}", "state": "", "baseline": False}
        return eid

    def resolve_dst(ip, port):
        if ip in lab_ips:
            return port_map.get((ip, port))
        if ip.startswith("192.168."):  # 10.x here is pod/service networking inside a cluster
            return ext(ip, port)
        return None

    def link(src, dst, port, how):
        if not src or not dst or src == dst or comps[src]["baseline"] or comps[dst]["baseline"]:
            return
        a = agg.setdefault((src, dst), {"src": src, "dst": dst, "ports": set(), "how": set()})
        a["ports"].add(port)
        a["how"].add(how)

    for ip, h in snap["hosts"].items():
        if h.get("error"):
            continue
        listening = {lst["port"] for lst in h["listen"]}
        for c in h["conns"]:
            if c["local_port"] in listening:
                continue  # inbound: recorded from the client's side
            key = cgroup_key(c["cgroup"])
            src = by_cg.get((ip, key)) or (adhoc_by_comm.get((ip, c["process"])) if key[0] == "session" else None)
            if key[0] == "session" and c["process"] in ("ssh", "sshd", "sshd-session"):
                continue
            link(src, resolve_dst(c["peer"], c["peer_port"]), c["peer_port"], "observed")
        for unit, targets in h.get("endpoints", {}).items():
            src = unit_alias.get((ip, unit)) or by_cg.get((ip, ("unit", unit)))
            for t in targets:
                thost, _, tport = t.rpartition(":")
                thost = {"localhost": ip, "127.0.0.1": ip}.get(thost, name_ip.get(thost, thost))
                if tport.isdigit():
                    link(src, resolve_dst(thost, int(tport)), int(tport), "configured")

    # Declared edges for flows neither config nor a live socket shows: "<src comp id> -> <ip>:<port>"
    if EXTRA_EDGES.exists():
        for line in EXTRA_EDGES.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            m = re.match(r"(\S+)\s*->\s*([\d.]+):(\d+)", line)
            if m and m.group(1) in comps:
                link(m.group(1), resolve_dst(m.group(2), int(m.group(3))), int(m.group(3)), "declared")
    return [{"src": a["src"], "dst": a["dst"], "ports": sorted(a["ports"]), "how": sorted(a["how"])}
            for a in agg.values()]


# ---------- classification ----------

SYSTEM = f"""You label the software running in a home lab so it can be drawn on a service map.
Lab hosts:
{LAB_HOSTS}

You get components with: id, host, runtime, name and hints (image, program, description, schedule, ports,
rule_guess). Choose exactly one category for each:
- ai-agent: a scheduled or long-running program that calls an LLM, an AI coding assistant session
  (Claude Code, opencode), an MCP client loop, or an AI traffic simulator
- ai-platform: LLM gateways, model servers, MCP servers, vector databases, AI search backends
- observability: metrics, logs, alerting, dashboards, exporters, monitoring agents
- security: API security sensors and security tooling
- network: API gateways, reverse proxies, ingress controllers, tunnels, zero-trust connectors, DNS
- ops: CI/CD, backups, maintenance jobs, repo mirrors, file shares, inventory/admin scripts
- platform: container runtimes, Kubernetes components, databases supporting other apps
- app: intentionally vulnerable demo/target apps and their parts (crAPI, Juice Shop, VAmPI, DVGA, mailhog)
Set "ai": true when the component uses, serves or is an AI/LLM capability, whatever its category.
"purpose": at most 12 words, plain English, specific to this lab; never invent hosts or versions.
Reply with ONLY JSON: {{"items": [{{"id": "...", "category": "...", "ai": true, "purpose": "..."}}]}}"""

HOST_SYSTEM = f"""You write one-line role summaries for hosts in a home lab.
Lab hosts:
{LAB_HOSTS}
For each host you get the notable components that run on it today. Write a role of at most 10 words:
lead with the host's purpose from the notes above, then the main things that actually run there
(skip exporters/collectors that run everywhere). If they disagree, trust the components. Reply with ONLY JSON: {{"hosts": [{{"ip": "...", "role": "..."}}]}}"""


def signature(c: dict) -> str:
    return "|".join(str(c.get(k, "")) for k in ("kind", "name", "image", "detail", "description", "namespace"))[:400]


def classify(model: dict, agent, reclassify: bool) -> dict:
    cache = {} if reclassify or not CACHE.exists() else json.loads(CACHE.read_text())
    comps = model["components"]
    for c in comps.values():
        guess, ai = rule_guess(c)
        c.update(category=guess, ai=ai, purpose=c.get("description", ""), classified_by="rules")
        hit = cache.get(signature(c))
        if hit:
            c.update(hit, classified_by="llm-cache")
    todo = [c for c in comps.values() if not c["baseline"] and c["classified_by"] == "rules"]
    stats = {"cached": sum(1 for c in comps.values() if c["classified_by"] == "llm-cache"), "asked": 0, "failed": 0}
    if agent and todo:
        by_host = defaultdict(list)
        for c in todo:
            by_host[c["host"] or "external"].append(c)
        for host, items in by_host.items():
            for i in range(0, len(items), 30):
                batch = items[i:i + 30]
                ids = {f"c{n}": c for n, c in enumerate(batch)}
                payload = [{"id": k, "host": f"{c['host']} {model['hosts'].get(c['host'], {}).get('name', '')}".strip(),
                            "runtime": RUNTIME_LABEL.get(c["kind"], c["kind"]), "name": c["name"],
                            **{f: c[f] for f in ("image", "detail", "description", "schedule", "namespace", "group")
                               if c.get(f)},
                            "ports": c.get("ports", [])[:4], "rule_guess": c["category"]}
                           for k, c in ids.items()]
                try:
                    res = agent.ask_json(SYSTEM, json.dumps(payload, indent=1))
                    for it in res.get("items", []):
                        c = ids.get(str(it.get("id")))
                        if not c or it.get("category") not in CAT_KEYS:
                            continue
                        hit = {"category": it["category"], "ai": bool(it.get("ai")),
                               "purpose": str(it.get("purpose", ""))[:120]}
                        c.update(hit, classified_by="llm")
                        cache[signature(c)] = hit
                        stats["asked"] += 1
                except Exception as ex:  # keep the rule-based labels for this batch
                    stats["failed"] += len(batch)
                    log(f"classify {host} batch failed: {type(ex).__name__}: {ex}")
        CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))

    # host roles (cached on the set of notable component names)
    roles_key = {}
    for ip, h in model["hosts"].items():
        notable = sorted(f"{c['name']} [{c['category']}]" for c in comps.values()
                         if ip in c["hosts"] and not c["baseline"])
        roles_key[ip] = (notable, hashlib.sha1(json.dumps(notable).encode()).hexdigest()[:12])
        h["role"] = cache.get(f"role|{ip}|{roles_key[ip][1]}", "")
    need = [ip for ip, h in model["hosts"].items() if not h["role"] and not h["error"]]
    if agent and need:
        try:
            res = agent.ask_json(HOST_SYSTEM, json.dumps(
                [{"ip": ip, "name": model["hosts"][ip]["name"], "components": roles_key[ip][0][:40]} for ip in need], indent=1))
            for it in res.get("hosts", []):
                ip = it.get("ip")
                if ip in need and it.get("role"):
                    model["hosts"][ip]["role"] = str(it["role"])[:90]
                    cache[f"role|{ip}|{roles_key[ip][1]}"] = model["hosts"][ip]["role"]
            CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True))
        except Exception as ex:
            log(f"host roles failed: {type(ex).__name__}: {ex}")
    return stats


# ---------- diff & fingerprint ----------

def fingerprint(model: dict) -> str:
    comps = sorted((c["id"], c["category"], c["state"], c.get("purpose", ""), c.get("schedule", ""),
                    tuple(c.get("ports", [])), c.get("image", "")) for c in model["components"].values())
    edges = sorted((x["src"], x["dst"], tuple(x["ports"])) for x in model["edges"])
    hosts = sorted((h["ip"], h["os"], h["kernel"], bool(h["error"]), h.get("role", "")) for h in model["hosts"].values())
    return hashlib.sha256(json.dumps([comps, edges, hosts]).encode()).hexdigest()[:16]


def diff(prev: dict, cur: dict) -> dict:
    if not prev:
        return {"first_run": True, "added": [], "removed": [], "changed": [], "hosts": []}
    pc = {k: v for k, v in prev["components"].items() if not v.get("baseline")}
    cc = {k: v for k, v in cur["components"].items() if not v.get("baseline")}
    changed = []
    for k in pc.keys() & cc.keys():
        a, b = pc[k], cc[k]
        for f in ("state", "image", "schedule"):
            if a.get(f) != b.get(f):
                changed.append({"id": k, "name": b["name"], "host": b.get("host", ""), "field": f,
                                "old": a.get(f), "new": b.get(f)})
    hosts = [{"ip": ip, "name": h["name"], "error": h["error"]} for ip, h in cur["hosts"].items()
             if h["error"] and not prev["hosts"].get(ip, {}).get("error")]
    hosts += [{"ip": ip, "name": h["name"], "kernel": (prev["hosts"].get(ip, {}).get("kernel"), h["kernel"])}
              for ip, h in cur["hosts"].items() if prev["hosts"].get(ip, {}).get("kernel") not in (None, h["kernel"])
              and h["kernel"]]
    ref = lambda c: {"id": c["id"], "name": c["name"], "host": c.get("host", ""), "kind": c["kind"],
                     "category": c.get("category", "")}
    return {"first_run": False, "added": [ref(cc[k]) for k in sorted(cc.keys() - pc.keys())],
            "removed": [ref(pc[k]) for k in sorted(pc.keys() - cc.keys())], "changed": changed, "hosts": hosts}


def change_count(d: dict) -> int:
    return len(d["added"]) + len(d["removed"]) + len(d["changed"]) + len(d["hosts"])


# ---------- views shared by HTML and README ----------

def host_group(h: dict) -> str:
    os_ = h["os"].lower()
    if "ubuntu" in os_ or "raspi" in h["kernel"]:
        return "Raspberry Pi 5"
    if "rocky linux 10" in os_ or "red hat" in os_:
        return "RHCSA practice lab"
    if "rocky" in os_:
        return "Core services (Hyper-V)"
    return "Other"


GROUP_ORDER = ["Core services (Hyper-V)", "Raspberry Pi 5", "RHCSA practice lab", "Other"]


def ipkey(ip: str):
    return tuple(int(x) for x in ip.split(".")) if re.match(r"^[\d.]+$", ip or "") else (999,)


def host_chips(model: dict, ip: str) -> list:
    """Notable components on a host, compose stacks of 3+ folded into one chip."""
    comps = [c for c in model["components"].values() if ip in c["hosts"] and not c["baseline"]]
    groups = defaultdict(list)
    for c in comps:
        if c["kind"] in ("podman-root", "podman", "docker") and c.get("group"):
            groups[(c["kind"], c["group"])].append(c)
        elif c["kind"] == "systemd" and c["name"].startswith("snap.") and c["name"].count(".") >= 2:
            groups[("systemd", c["name"].split(".")[1])].append(c)
    folded = {c["id"] for g in groups.values() if len(g) >= 3 for c in g}
    chips = [{"name": c["name"], "category": c["category"], "ai": c["ai"], "kind": c["kind"], "comp": c,
              "title": c.get("purpose", ""), "count": c.get("count", 1), "state": c.get("state", "")}
             for c in comps if c["id"] not in folded]
    for (kind, grp), members in groups.items():
        if len(members) < 3:
            continue
        cat = Counter(m["category"] for m in members).most_common(1)[0][0]
        if kind != "systemd" and grp in ("docker", "compose", "deploy", "app", "default"):
            ns = Counter(m["image"].split("/")[-2] for m in members if m.get("image", "").count("/") >= 1
                         and m["image"].split("/")[-2] not in ("library", "docker.io"))
            grp = ns.most_common(1)[0][0] if ns else grp
        chips.append({"name": f"{grp} stack" if kind != "systemd" else f"{grp} (snap)", "category": cat, "ai": any(m["ai"] for m in members), "kind": kind,
                      "comp": None, "title": f"{len(members)} {'units' if kind == 'systemd' else 'containers'}: " + ", ".join(m["name"] for m in members),
                      "count": len(members), "state": "running" if all(m["state"] == "running" for m in members) else "partial"})
    chips.sort(key=lambda x: (CAT_KEYS.index(x["category"]), x["name"].lower()))
    return chips


def ai_graph(model: dict):
    """Nodes/edges touching AI components (plus one hop), with fleet-wide duplicates merged."""
    comps = model["components"]
    ai = {k for k, c in comps.items() if c.get("ai") or c.get("category") in ("ai-agent", "ai-platform")
          or (c["kind"] == "external" and "LM Studio" in c["name"])}
    edges = [x for x in model["edges"] if x["src"] in ai or x["dst"] in ai]
    nodes = {n for x in edges for n in (x["src"], x["dst"])} | {k for k in ai if not comps[k]["baseline"]}
    return nodes, edges


def layer(nodes: set, edges: list) -> dict:
    out = defaultdict(set)
    for x in edges:
        out[x["src"]].add(x["dst"])
    indeg = Counter(x["dst"] for x in edges)
    depth = {n: 0 for n in nodes}
    order = sorted(nodes, key=lambda n: (indeg[n] > 0, n))
    for _ in range(len(nodes)):  # longest path, capped (cycles stop growing)
        changed = False
        for n in order:
            for m in out[n]:
                if depth[m] < depth[n] + 1 and depth[n] + 1 < len(nodes):
                    depth[m] = depth[n] + 1
                    changed = True
        if not changed:
            break
    return depth


# ---------- HTML ----------

CSS = """
:root{
  --ground:#E9EDF1; --surface:#FFFFFF; --surface2:#F4F6F8; --ink:#141B23; --ink2:#3A4655; --muted:#58657A; --line:#CBD3DC;
  --good:#0ca30c; --warn:#B42318; --warn-bg:#FDECEA;
  --c-ai-agent:#2a78d6; --c-ai-platform:#eb6834; --c-observability:#1baf7a; --c-security:#eda100;
  --c-network:#e87ba4; --c-ops:#008300; --c-platform:#6250d6; --c-app:#e34948; --c-none:#8F9CAD;
  --display:"Chakra Petch","Rajdhani","Segoe UI",system-ui,sans-serif;
  --body:"IBM Plex Sans","Segoe UI",system-ui,sans-serif; --mono:"IBM Plex Mono",ui-monospace,Menlo,monospace;
}
@media (prefers-color-scheme: dark){ :root:not([data-theme="light"]){ DARK } }
:root[data-theme="dark"]{ DARK }
*{box-sizing:border-box}
body{margin:0;background:var(--ground);color:var(--ink);font-family:var(--body);font-size:14px;line-height:1.5}
.wrap{max-width:1400px;margin:0 auto;padding:24px 16px 56px}
h1,h2,h3{font-family:var(--display);margin:0;letter-spacing:.01em;text-wrap:balance}
h1{font-size:clamp(28px,4vw,44px);line-height:1.05}
h2{font-size:22px;margin:36px 0 4px}
.eyebrow{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted)}
.lede{color:var(--ink2);max-width:80ch;margin:8px 0 0}
.sub{color:var(--muted);margin:0 0 12px;font-size:13px}
.mono{font-family:var(--mono)}
a{color:inherit}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:20px 0}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-family:var(--display);font-size:30px;line-height:1.1}
.tile span{color:var(--muted);font-size:12px}
@media (min-width:760px){.toolbar{position:sticky;top:0}}
.toolbar{z-index:5;background:color-mix(in srgb,var(--ground) 92%,transparent);backdrop-filter:blur(6px);
  padding:10px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center;border-bottom:1px solid var(--line)}
.toolbar input[type=search]{flex:1 1 220px;min-width:0;padding:7px 10px;border-radius:8px;border:1px solid var(--line);
  background:var(--surface);color:var(--ink);font:inherit}
.legend{display:flex;flex-wrap:wrap;gap:6px}
.lg{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:99px;border:1px solid var(--line);
  background:var(--surface);color:var(--ink);font:inherit;font-size:12px;cursor:pointer}
.lg[aria-pressed=false]{opacity:.45}
.dot{width:10px;height:10px;border-radius:3px;flex:none;display:inline-block}
label.chk{font-size:12px;color:var(--muted);display:inline-flex;gap:6px;align-items:center}
.changes{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin-top:8px}
.changes ul{margin:4px 0 0;padding-left:18px}
.add{color:var(--good)} .rem{color:var(--warn)}
.group h3{font-size:15px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin:20px 0 8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}
.host{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.host.err{border-color:var(--warn);background:var(--warn-bg)}
.host header{display:flex;justify-content:space-between;gap:8px;align-items:baseline}
.host h4{margin:0;font-family:var(--display);font-size:17px}
.host .ip{font-family:var(--mono);font-size:12px;color:var(--muted)}
.host .role{color:var(--ink2);font-size:13px;margin:2px 0 6px}
.host .meta{font-size:11px;color:var(--muted);font-family:var(--mono);margin-bottom:8px}
.chips{display:flex;flex-wrap:wrap;gap:5px}
.chip{display:inline-flex;align-items:center;gap:5px;max-width:100%;padding:2px 8px 2px 6px;border-radius:6px;
  background:var(--surface2);border:1px solid var(--line);font-size:12px;cursor:default}
.chip .dot{width:8px;height:8px;border-radius:2px}
.chip small{color:var(--muted);font-family:var(--mono);font-size:10px}
.chip.ai{box-shadow:inset 0 0 0 1px var(--c-ai-agent)}
.chip.bad{border-color:var(--warn)}
.chip .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hidden{display:none!important}
.baseline{display:none}
body.show-baseline .baseline{display:revert}
.figure{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:12px;overflow-x:auto}
.figure svg{display:block;min-width:720px;width:100%;height:auto}
svg text{font-family:var(--body);fill:var(--ink)}
svg .muted{fill:var(--muted)}
svg .edge{fill:none;stroke:var(--muted);stroke-width:1.5;opacity:.55}
svg .edge.configured,svg .edge.declared{stroke-dasharray:5 4}
svg .edge.hl{stroke:var(--ink);opacity:1;stroke-width:2.5}
svg .node rect.box{fill:var(--surface2);stroke:var(--line)}
svg .node:hover rect.box{stroke:var(--ink)}
svg .dim{opacity:.25}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th{text-align:left;font-weight:600;color:var(--muted);border-bottom:1px solid var(--line);padding:5px 8px;white-space:nowrap}
td{border-bottom:1px solid color-mix(in srgb,var(--line) 50%,transparent);padding:4px 8px;vertical-align:top}
td.mono,td .mono{font-size:11.5px;word-break:break-all}
details{background:var(--surface);border:1px solid var(--line);border-radius:10px;margin:8px 0;padding:0 12px}
details summary{cursor:pointer;padding:10px 0;font-weight:600}
details[open] summary{border-bottom:1px solid var(--line);margin-bottom:8px}
.tablewrap{overflow-x:auto;padding-bottom:10px}
.state-bad{color:var(--warn);font-weight:600}
footer{margin-top:40px;color:var(--muted);font-size:12px}
"""
DARK = ("--ground:#0C1117; --surface:#141B24; --surface2:#1A2330; --ink:#E4E9EF; --ink2:#C3CCD6; --muted:#8F9CAD; "
        "--line:#2A3542; --warn:#FF8A7A; --warn-bg:#3A1714; --c-ai-agent:#3987e5; --c-ai-platform:#d95926; "
        "--c-observability:#199e70; --c-security:#c98500; --c-network:#d55181; --c-ops:#008300; "
        "--c-platform:#9085e9; --c-app:#e66767;")

JS = """
(function(){
  var p=new URLSearchParams(location.search);
  if(p.get('theme')) document.documentElement.setAttribute('data-theme',p.get('theme'));
  if(p.has('baseline')) document.body.classList.add('show-baseline');
  var q=document.getElementById('q'), off={};
  function apply(){
    var t=(q.value||'').toLowerCase();
    document.querySelectorAll('[data-f]').forEach(function(el){
      var ok=(!t||el.getAttribute('data-f').indexOf(t)>=0)&&!off[el.getAttribute('data-cat')];
      el.classList.toggle('hidden',!ok);
    });
  }
  q.addEventListener('input',apply);
  document.querySelectorAll('.lg[data-cat]').forEach(function(b){
    b.addEventListener('click',function(){var c=b.getAttribute('data-cat');off[c]=!off[c];
      b.setAttribute('aria-pressed',off[c]?'false':'true');apply();});
  });
  var bl=document.getElementById('bl');
  bl.checked=document.body.classList.contains('show-baseline');
  bl.addEventListener('change',function(){document.body.classList.toggle('show-baseline',bl.checked);});
  document.querySelectorAll('svg .node').forEach(function(n){
    var id=n.getAttribute('data-id');
    n.addEventListener('mouseenter',function(){
      var svg=n.ownerSVGElement, keep={}; keep[id]=1;
      svg.querySelectorAll('.edge').forEach(function(e){
        var hit=e.getAttribute('data-s')===id||e.getAttribute('data-d')===id;
        e.classList.toggle('hl',hit); if(hit){keep[e.getAttribute('data-s')]=1;keep[e.getAttribute('data-d')]=1;}
      });
      svg.querySelectorAll('.node').forEach(function(m){m.classList.toggle('dim',!keep[m.getAttribute('data-id')]);});
    });
    n.addEventListener('mouseleave',function(){var svg=n.ownerSVGElement;
      svg.querySelectorAll('.edge').forEach(function(e){e.classList.remove('hl');});
      svg.querySelectorAll('.node').forEach(function(m){m.classList.remove('dim');});});
  });
})();
"""


def ftext(*parts) -> str:
    return e(" ".join(str(p) for p in parts if p).lower())


def chip_html(ch: dict, host: dict) -> str:
    c = ch["comp"] or {}
    bad = ch["state"] in ("failed", "exited", "degraded", "partial", "dead")
    tip = " · ".join(x for x in (CAT_LABEL[ch["category"]], RUNTIME_LABEL.get(ch["kind"], ch["kind"]),
                                 ch["title"], c.get("schedule", ""), ", ".join(c.get("ports", [])[:3]),
                                 ch["state"] if bad else "") if x)
    count = f" ×{ch['count']}" if ch["count"] > 1 else ""
    return (f'<span class="chip{" ai" if ch["ai"] else ""}{" bad" if bad else ""}" data-cat="{ch["category"]}" '
            f'data-f="{ftext(ch["name"], ch["title"], ch["category"], ch["kind"], host["name"], "ai" if ch["ai"] else "")}" '
            f'title="{e(tip)}"><i class="dot" style="background:var(--c-{ch["category"]})"></i>'
            f'<span class="nm">{e(ch["name"])}{count}</span><small>{e(RUNTIME_LABEL.get(ch["kind"], ch["kind"]))}</small></span>')


def svg_graph(model: dict, nodes: set, edges: list) -> str:
    comps = model["components"]
    if not nodes:
        return '<p class="sub">No AI components found.</p>'
    depth = layer(nodes, edges)
    linked = {n for x in edges for n in (x["src"], x["dst"])}
    top = max(depth.values()) if depth else 0
    for n in nodes - linked:  # unlinked today: place by role, not as a "caller"
        depth[n] = 0 if comps[n].get("category") == "ai-agent" else min(1, top)
    cols = defaultdict(list)
    for n in nodes:
        cols[depth[n]].append(n)
    W, H, GX, GY, PAD = 230, 40, 110, 10, 16
    pos = {}
    for d, ns in cols.items():
        ns.sort(key=lambda n: (CAT_KEYS.index(comps[n].get("category", "ops")) if comps[n].get("category") in CAT_KEYS else 9,
                               ipkey(comps[n].get("host", "")), comps[n]["name"]))
        for i, n in enumerate(ns):
            pos[n] = (PAD + d * (W + GX), PAD + 26 + i * (H + GY))
    width = PAD * 2 + (max(cols) + 1) * W + max(cols) * GX
    height = PAD * 2 + 26 + max(len(v) for v in cols.values()) * (H + GY)
    heads = {0: "Callers", max(cols): "Backends"} if max(cols) > 0 else {0: "AI components"}
    out = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="Dependency map of AI agents and AI platform">']
    for d in cols:
        label = heads.get(d, "AI platform / services" if d == 1 else f"hop {d}")
        out.append(f'<text x="{PAD + d * (W + GX)}" y="{PAD + 12}" class="muted" font-size="11" '
                   f'letter-spacing="1.5">{e(label.upper())}</text>')
    for x in edges:
        (x1, y1), (x2, y2) = pos[x["src"]], pos[x["dst"]]
        sx, sy, tx, ty = x1 + W, y1 + H / 2, x2, y2 + H / 2
        if tx <= sx:  # same/back column: loop around below
            path = f"M{sx},{sy} C{sx + 60},{sy + 60} {tx - 60},{ty + 60} {tx},{ty}"
        else:
            mx = (sx + tx) / 2
            path = f"M{sx},{sy} C{mx},{sy} {mx},{ty} {tx},{ty}"
        how = "observed" if "observed" in x["how"] else x["how"][0]
        tip = f"{comps[x['src']]['name']} → {comps[x['dst']]['name']} :{','.join(map(str, x['ports']))} ({', '.join(x['how'])})"
        out.append(f'<path class="edge {how}" data-s="{e(x["src"])}" data-d="{e(x["dst"])}" d="{path}" '
                   f'marker-end="url(#arr)"><title>{e(tip)}</title></path>')
    for n, (x, y) in pos.items():
        c = comps[n]
        cat = c.get("category") if c.get("category") in CAT_KEYS else "none"
        hn = model["hosts"].get(c.get("host", ""), {}).get("name", "") or c.get("detail", "")
        sub = f"{hn} · {RUNTIME_LABEL.get(c['kind'], c['kind'])}"
        name = c["name"] if len(c["name"]) <= 30 else c["name"][:29] + "…"
        out.append(f'<g class="node" data-id="{e(n)}"><title>{e(c.get("purpose") or c.get("description") or c["name"])}</title>'
                   f'<rect class="box" x="{x}" y="{y}" width="{W}" height="{H}" rx="6"/>'
                   f'<rect x="{x}" y="{y}" width="5" height="{H}" rx="2" style="fill:var(--c-{cat})"/>'
                   f'<text x="{x + 13}" y="{y + 16}" font-size="12.5" font-weight="600">{e(name)}</text>'
                   f'<text x="{x + 13}" y="{y + 31}" font-size="10.5" class="muted">{e(sub[:40])}</text></g>')
    out.insert(1, '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
                  'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--muted)"/></marker></defs>')
    out.append("</svg>")
    return "".join(out)


def comp_rows(model: dict, comps: list) -> str:
    rows = []
    for c in sorted(comps, key=lambda c: (c["baseline"], CAT_KEYS.index(c["category"]) if c["category"] in CAT_KEYS else 9,
                                          c["kind"], c["name"].lower())):
        bad = c.get("state") in ("failed", "exited", "degraded", "dead")
        where = c.get("schedule") or ", ".join(c.get("ports", [])[:4])
        rows.append(
            f'<tr class="{"baseline" if c["baseline"] else ""}" data-cat="{c["category"]}" '
            f'data-f="{ftext(c["name"], c.get("purpose"), c["category"], c["kind"], c.get("detail"), c.get("image"), "ai" if c["ai"] else "")}">'
            f'<td><i class="dot" style="background:var(--c-{c["category"]})"></i> {e(c["name"])}'
            f'{" ×" + str(c["count"]) if c.get("count", 1) > 1 else ""}</td>'
            f'<td>{e(RUNTIME_LABEL.get(c["kind"], c["kind"]))}{" · " + e(c["user"]) if c.get("user") not in (None, "", "root") else ""}</td>'
            f'<td>{e(CAT_LABEL.get(c["category"], ""))}{" · AI" if c["ai"] else ""}{" · baseline" if c["baseline"] else ""}</td>'
            f'<td>{e(c.get("purpose", ""))}</td>'
            f'<td class="{"state-bad" if bad else ""}">{e(c.get("state", ""))}</td>'
            f'<td class="mono">{e(where)}</td><td class="mono">{e(c.get("image") or c.get("detail", ""))}</td></tr>')
    return ("<div class=\"tablewrap\"><table><tr><th>Component</th><th>Runtime</th><th>Category</th><th>Purpose</th>"
            "<th>State</th><th>Schedule / ports</th><th>Image / program</th></tr>" + "".join(rows) + "</table></div>")


def render(model: dict, changes: dict, footer: str) -> str:
    comps = model["components"]
    hosts = model["hosts"]
    notable = [c for c in comps.values() if not c["baseline"] and c["kind"] != "external"]
    ctr = [c for c in comps.values() if c["kind"] in ("podman", "podman-root", "docker")]
    tiles = [
        (sum(1 for h in hosts.values() if not h["error"]), f"hosts mapped ({len(hosts)} in Grafana scope)"),
        (sum(1 for c in notable if c["kind"] in ("systemd", "user-unit")), "services (excl. OS baseline)"),
        (sum(1 for c in notable if c["kind"] in ("timer", "cron")), "scheduled jobs"),
        (f"{sum(1 for c in ctr if c['state'] == 'running')}/{len(ctr)}", "containers running"),
        (sum(1 for c in notable if c["kind"] == "k8s"), "k8s workloads"),
        (sum(1 for c in notable if c["ai"]), "AI components"),
        ("first run" if changes["first_run"] else change_count(changes), "changes since last map"),
    ]
    h = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Lab Service Map</title>'
         f'<meta name="viewport" content="width=device-width, initial-scale=1">'
         f'<meta name="servicemap-fingerprint" content="{model["fingerprint"]}">'
         '<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
         '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@600;700&family=IBM+Plex+Sans:wght@400;600&family=IBM+Plex+Mono:wght@400&display=swap">'
         f'<style>{CSS.replace("DARK", DARK)}</style></head><body><div class="wrap">',
         f'<div class="eyebrow">Cropsey lab · 192.168.1.x · service map</div><h1>What’s running in the lab</h1>'
         f'<p class="lede">Every systemd service, timer, cron job, podman (rootless and root) and docker container, '
         f'Kubernetes workload and long-running script on the hosts Grafana monitors, collected over SSH and labelled by '
         f'servicemap-agent. Mapped {e(model["generated_at"][:16].replace("T", " "))} (America/Chicago).</p>',
         '<div class="tiles">' + "".join(f'<div class="tile"><b>{e(v)}</b><span>{e(l)}</span></div>' for v, l in tiles) + "</div>"]

    if not changes["first_run"]:
        items = ([f'<li class="add">+ {e(c["name"])} <span class="sub">({e(RUNTIME_LABEL.get(c["kind"], c["kind"]))} on '
                  f'{e(hosts.get(c["host"], {}).get("name", c["host"]))})</span></li>' for c in changes["added"]] +
                 [f'<li class="rem">− {e(c["name"])} <span class="sub">({e(RUNTIME_LABEL.get(c["kind"], c["kind"]))} on '
                  f'{e(hosts.get(c["host"], {}).get("name", c["host"]))})</span></li>' for c in changes["removed"]] +
                 [f'<li>{e(c["name"])} on {e(hosts.get(c["host"], {}).get("name", c["host"]))}: {e(c["field"])} '
                  f'{e(c["old"])} → {e(c["new"])}</li>' for c in changes["changed"]] +
                 [f'<li class="rem">{e(x["name"])}: {e(x.get("error") or "kernel " + " → ".join(map(str, x["kernel"])))}</li>'
                  for x in changes["hosts"]])
        h.append('<div class="changes"><b>Since the last map</b>' +
                 (f'<ul>{"".join(items[:60])}</ul>' if items else '<p class="sub">No changes.</p>') + "</div>")

    h.append('<div class="toolbar"><input type="search" id="q" placeholder="Filter: name, image, host, “ai”…" '
             'aria-label="Filter components"><div class="legend">' +
             "".join(f'<button class="lg" data-cat="{k}" aria-pressed="true" title="{e(d)}">'
                     f'<i class="dot" style="background:var(--c-{k})"></i>{e(lbl)}</button>' for k, lbl, d in CATS) +
             '</div><label class="chk"><input type="checkbox" id="bl"> show OS baseline</label></div>')

    # fleet map
    h.append('<h2>Fleet map</h2><p class="sub">Each card is a host Grafana monitors; chips are what runs on it, '
             'coloured by category, with the runtime in small type. Hover a chip for its purpose. Outlined chips are AI; '
             'red-bordered chips are failed/exited. Compose stacks of 3+ containers are folded into one chip.</p>')
    by_group = defaultdict(list)
    for ip, hh in hosts.items():
        by_group[host_group(hh)].append(ip)
    for g in GROUP_ORDER:
        if g not in by_group:
            continue
        h.append(f'<div class="group"><h3>{e(g)}</h3><div class="grid">')
        for ip in sorted(by_group[g], key=ipkey):
            hh = hosts[ip]
            if hh["error"]:
                h.append(f'<div class="host err"><header><h4>{e(hh["name"])}</h4><span class="ip">{e(ip)}</span></header>'
                         f'<div class="role">unreachable: {e(hh["error"][:160])}</div></div>')
                continue
            chips = host_chips(model, ip)
            n_base = sum(1 for c in comps.values() if ip in c["hosts"] and c["baseline"])
            h.append(f'<div class="host"><header><h4>{e(hh["name"])}</h4><span class="ip">{e(ip)}</span></header>'
                     f'<div class="role">{e(hh.get("role", ""))}</div>'
                     f'<div class="meta">{e(hh["os"])} · {e(hh["cpus"])} vCPU · {e(hh["mem_gb"])} GB · '
                     f'{n_base} baseline units hidden</div>'
                     f'<div class="chips">{"".join(chip_html(ch, hh) for ch in chips)}</div></div>')
        h.append("</div></div>")

    # AI dependency map
    nodes, edges = ai_graph(model)
    h.append('<h2>AI agents &amp; dependencies</h2><p class="sub">Every AI component and what it talks to. '
             'Solid = live connection seen at collection time; dashed = configured in the service’s environment '
             '(or declared in extra-edges.conf). Hover a box to trace its links.</p>'
             f'<div class="figure">{svg_graph(model, nodes, edges)}</div>')

    # all cross-host flows
    rows = []
    for x in sorted(model["edges"], key=lambda x: (ipkey(comps[x["src"]].get("host", "")), comps[x["src"]]["name"])):
        s, d = comps[x["src"]], comps[x["dst"]]
        sh_ = hosts.get(s.get("host", ""), {}).get("name", "")
        dh_ = hosts.get(d.get("host", ""), {}).get("name", "") or d.get("detail", "")
        rows.append(f'<tr data-cat="{d.get("category", "ops")}" data-f="{ftext(s["name"], d["name"], sh_, dh_)}">'
                    f'<td>{e(s["name"])} <span class="sub">{e(sh_)}</span></td><td>→</td>'
                    f'<td>{e(d["name"])} <span class="sub">{e(dh_)}</span></td>'
                    f'<td class="mono">{e(", ".join(map(str, x["ports"])))}</td><td>{e(", ".join(x["how"]))}</td></tr>')
    h.append(f'<details><summary>All dependencies ({len(rows)} links between components)</summary><div class="tablewrap">'
             '<table><tr><th>From</th><th></th><th>To</th><th>Port</th><th>Seen as</th></tr>' + "".join(rows) +
             "</table></div></details>")

    # kubernetes
    if model["clusters"]:
        h.append('<h2>Kubernetes</h2>')
        for cl in model["clusters"]:
            ws = [comps[w] for w in cl["workloads"]]
            rows = "".join(
                f'<tr class="{"baseline" if w["baseline"] else ""}" data-cat="{w["category"]}" '
                f'data-f="{ftext(w["name"], w["namespace"], w.get("image"), w.get("purpose"))}">'
                f'<td><i class="dot" style="background:var(--c-{w["category"]})"></i> {e(w["name"])}</td>'
                f'<td>{e(w["namespace"])}</td><td>{e(w["k8s_kind"])}</td>'
                f'<td class="{"state-bad" if w["state"] == "degraded" else ""}">{e(w.get("ready"))}/{e(w.get("replicas"))}</td>'
                f'<td>{e(", ".join(hosts.get(i, {}).get("name", i) for i in w["hosts"]))}</td>'
                f'<td>{e(w.get("restarts", 0))}</td><td>{e(w.get("purpose", ""))}</td>'
                f'<td class="mono">{e(w.get("image", ""))}</td></tr>' for w in sorted(ws, key=lambda w: (w["baseline"], w["namespace"], w["name"])))
            h.append(f'<details open><summary>{e(cl["name"])} — {sum(1 for w in ws if not w["baseline"])} workloads '
                     f'({sum(1 for w in ws if w["baseline"])} system)</summary><div class="tablewrap"><table><tr><th>Workload</th>'
                     '<th>Namespace</th><th>Kind</th><th>Ready</th><th>Nodes</th><th>Restarts</th><th>Purpose</th>'
                     f'<th>Images</th></tr>{rows}</table></div></details>')

    # per-host inventory
    h.append('<h2>Host inventory</h2><p class="sub">Everything found on each host. Tick “show OS baseline” to include '
             'distro services (sshd, chronyd, NetworkManager, …).</p>')
    for ip in sorted(hosts, key=ipkey):
        hh = hosts[ip]
        if hh["error"]:
            continue
        hc = [c for c in comps.values() if ip in c["hosts"] and c["kind"] != "k8s"]
        ports = ", ".join(f'{x["port"]}{"/" + x["component"] if x["component"] else ("/" + x["process"] if x["process"] else "")}'
                          for x in hh["listen"])
        h.append(f'<details><summary>{e(hh["name"])} <span class="sub">{e(ip)} · {sum(1 for c in hc if not c["baseline"])} '
                 f'components · {sum(1 for c in hc if c["baseline"])} baseline</span></summary>'
                 f'<p class="sub">{e(hh["os"])} · kernel {e(hh["kernel"])} · up since {e(hh["booted"])}</p>'
                 f'{comp_rows(model, hc)}<p class="sub mono">Listening TCP: {e(ports)}</p></details>')

    h.append(f'<footer>{e(footer)} · fingerprint {model["fingerprint"]} · '
             f'<a href="{REPO_URL}">history on GitHub</a></footer></div><script>{JS}</script></body></html>')
    return "".join(h)


# ---------- standalone images (Grafana Text panels can show <img>, not iframes) ----------

THEMES = {
    "dark": {"bg": "#141B24", "card": "#1A2330", "chip": "#202B3A", "ink": "#E4E9EF", "muted": "#8F9CAD",
             "line": "#2A3542", "warn": "#FF8A7A", **{f"c-{k}": v for k, v in zip(CAT_KEYS, (
                 "#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"))}},
    "light": {"bg": "#FFFFFF", "card": "#F4F6F8", "chip": "#FFFFFF", "ink": "#141B23", "muted": "#58657A",
              "line": "#CBD3DC", "warn": "#B42318", **{f"c-{k}": v for k, v in zip(CAT_KEYS, (
                  "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"))}},
}


def standalone(svg: str, theme: str) -> str:
    t = THEMES[theme]
    var = ";".join(f"--{k}:{v}" for k, v in t.items() if k.startswith("c-")) + ";--c-none:" + t["muted"]
    style = (f"<style>svg{{{var};background:{t['bg']}}}text{{font-family:'IBM Plex Sans','Segoe UI',system-ui,sans-serif;"
             f"fill:{t['ink']}}}.muted{{fill:{t['muted']}}}.edge{{fill:none;stroke:{t['muted']};stroke-width:1.5;opacity:.6}}"
             f".edge.configured,.edge.declared{{stroke-dasharray:5 4}}.node rect.box{{fill:{t['card']};stroke:{t['line']}}}"
             f".card{{fill:{t['card']};stroke:{t['line']}}}.chipbox{{fill:{t['chip']};stroke:{t['line']}}}"
             f".bad{{stroke:{t['warn']}}}.airing{{stroke:var(--c-ai-agent)}}.arrow{{fill:{t['muted']}}}</style>")
    svg = svg.replace('style="fill:var(--muted)"', 'class="arrow"')
    svg = re.sub(r"^<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', svg)
    return svg.replace(">", ">" + style, 1)


def fleet_svg(model: dict) -> str:
    """Host cards with wrapped chips, laid out in columns; text widths are estimated."""
    W, COLS, GAP, PAD = 1600, 4, 14, 16
    cw = (W - 2 * PAD - (COLS - 1) * GAP) / COLS
    hosts = model["hosts"]
    out, y = [], PAD
    by_group = defaultdict(list)
    for ip, hh in hosts.items():
        by_group[host_group(hh)].append(ip)
    for g in GROUP_ORDER:
        if g not in by_group:
            continue
        out.append(f'<text x="{PAD}" y="{y + 14}" font-size="13" class="muted" letter-spacing="1.5">{e(g.upper())}</text>')
        y += 24
        cards = []
        for ip in sorted(by_group[g], key=ipkey):
            hh = hosts[ip]
            chips = [] if hh["error"] else host_chips(model, ip)
            parts, cx, cy = [], 12, 74
            for ch in chips:
                label = ch["name"] + (f" ×{ch['count']}" if ch["count"] > 1 else "")
                rt = RUNTIME_LABEL.get(ch["kind"], ch["kind"])
                w = 24 + len(label) * 6.6 + len(rt) * 6.0 + 10  # generous: <img> SVGs fall back to system fonts
                if cx + w > cw - 10 and cx > 12:
                    cx, cy = 12, cy + 24
                bad = ch["state"] in ("failed", "exited", "degraded", "partial", "dead")
                cls = "chipbox" + (" bad" if bad else (" airing" if ch["ai"] else ""))
                parts.append(f'<g><title>{e(ch["title"])}</title><rect class="{cls}" x="{cx}" y="{cy}" width="{w:.0f}" height="19" rx="4"/>'
                             f'<rect x="{cx + 6}" y="{cy + 6}" width="8" height="8" rx="2" style="fill:var(--c-{ch["category"]})"/>'
                             f'<text x="{cx + 19}" y="{cy + 13.5}" font-size="11.5">{e(label)}'
                             f'<tspan class="muted" font-size="9.5" dx="5">{e(rt)}</tspan></text></g>')
                cx += w + 5
            role = hh.get("role") or ("unreachable: " + hh["error"])
            role = role if len(role) <= int(cw / 6.8) else role[:int(cw / 6.8) - 1] + "…"
            meta = f'{hh["os"]} · {hh["cpus"]} vCPU · {hh["mem_gb"]} GB'
            cards.append((cy + 30, f'<text x="12" y="24" font-size="16" font-weight="700">{e(hh["name"])}</text>'
                                   f'<text x="{cw - 12}" y="24" font-size="11" class="muted" text-anchor="end">{e(ip)}</text>'
                                   f'<text x="12" y="44" font-size="12">{e(role)}</text>'
                                   f'<text x="12" y="62" font-size="10.5" class="muted">{e(meta[:80])}</text>' + "".join(parts),
                          bool(hh["error"])))
        for row in range(0, len(cards), COLS):
            rh = max(c[0] for c in cards[row:row + COLS])
            for i, (h_, inner, err) in enumerate(cards[row:row + COLS]):
                x = PAD + i * (cw + GAP)
                out.append(f'<g transform="translate({x:.0f},{y})"><rect class="card{" bad" if err else ""}" '
                           f'width="{cw:.0f}" height="{rh}" rx="10"/>{inner}</g>')
            y += rh + GAP
        y += 8
    # legend
    lx = PAD
    for k, lbl, _ in CATS:
        out.append(f'<rect x="{lx}" y="{y + 4}" width="10" height="10" rx="2" style="fill:var(--c-{k})"/>'
                   f'<text x="{lx + 15}" y="{y + 13}" font-size="12">{e(lbl)}</text>')
        lx += 30 + len(lbl) * 7
    out.append(f'<text x="{W - PAD}" y="{y + 13}" font-size="11" class="muted" text-anchor="end">'
               f'mapped {e(model["generated_at"][:16].replace("T", " "))} · servicemap-agent</text>')
    return f'<svg viewBox="0 0 {W} {y + 26}" width="{W}" height="{y + 26}">' + "".join(out) + "</svg>"


def metrics(model: dict, changes: dict) -> str:
    """Prometheus exposition of the map (served as /metrics on :9440) for native Grafana tables."""
    q = lambda v: str(v if v is not None else "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
    comps, hosts = model["components"], model["hosts"]
    lines = ["# HELP servicemap_component_info A component on the lab service map (value 1).",
             "# TYPE servicemap_component_info gauge"]
    for c in sorted(comps.values(), key=lambda c: c["id"]):
        if c["baseline"] or c["kind"] == "external":
            continue
        for ip in c["hosts"] or [""]:
            lines.append(
                f'servicemap_component_info{{host="{q(hosts.get(ip, {}).get("name", ip))}",ip="{ip}",name="{q(c["name"])}",'
                f'runtime="{q(RUNTIME_LABEL.get(c["kind"], c["kind"]))}",category="{q(CAT_LABEL.get(c["category"], ""))}",'
                f'ai="{str(bool(c["ai"])).lower()}",state="{q(c.get("state"))}",purpose="{q(c.get("purpose"))}",'
                f'schedule="{q(c.get("schedule"))}",image="{q(c.get("image") or c.get("detail"))}"}} 1')
    lines += ["# HELP servicemap_edge_info A dependency between two components (value 1).", "# TYPE servicemap_edge_info gauge"]
    for x in model["edges"]:
        s_, d_ = comps[x["src"]], comps[x["dst"]]
        lines.append(f'servicemap_edge_info{{src="{q(s_["name"])}",src_host="{q(hosts.get(s_.get("host", ""), {}).get("name", ""))}",'
                     f'dst="{q(d_["name"])}",dst_host="{q(hosts.get(d_.get("host", ""), {}).get("name", "") or d_.get("detail", ""))}",'
                     f'port="{",".join(map(str, x["ports"]))}",how="{",".join(x["how"])}"}} 1')
    count = Counter((hosts.get(c["host"], {}).get("name", ""), CAT_LABEL[c["category"]]) for c in comps.values()
                    if not c["baseline"] and c["kind"] != "external")
    lines += ["# HELP servicemap_components Notable components per host and category.", "# TYPE servicemap_components gauge"]
    lines += [f'servicemap_components{{host="{q(h)}",category="{q(cat)}"}} {n}' for (h, cat), n in sorted(count.items())]
    ok = sum(1 for h in hosts.values() if not h["error"])
    lines += ["# HELP servicemap_hosts Hosts in scope by collection state.", "# TYPE servicemap_hosts gauge", f"servicemap_hosts{{state=\"ok\"}} {ok}",
              f"servicemap_hosts{{state=\"unreachable\"}} {len(hosts) - ok}",
              "# HELP servicemap_changes Component changes since the previous map.", "# TYPE servicemap_changes gauge", f"servicemap_changes {0 if changes['first_run'] else change_count(changes)}",
              "# HELP servicemap_last_run_timestamp_seconds When the snapshot behind the map was collected.",
              "# TYPE servicemap_last_run_timestamp_seconds gauge",
              f"servicemap_last_run_timestamp_seconds {dt.datetime.fromisoformat(model['generated_at']).timestamp():.0f}"]
    return "\n".join(lines) + "\n"


# ---------- README (GitHub) ----------

def mermaid_id(s: str) -> str:
    return "n" + hashlib.sha1(s.encode()).hexdigest()[:8]


def render_readme(model: dict, changes: dict) -> str:
    comps, hosts = model["components"], model["hosts"]
    lines = ["# Lab service map", "",
             f"Generated **{model['generated_at'][:16].replace('T', ' ')}** (America/Chicago) by "
             "[servicemap-agent](https://github.com/mcropsey/mikes-agents/tree/main/servicemap-agent) on .98. "
             "Live page (in Grafana and on the lab network): "
             f"`{PAGE_URL}`. Open [`index.html`](index.html) locally for the interactive version.", ""]
    if not changes["first_run"]:
        lines += ["## Changes since the previous map", ""]
        ch = ([f"- ➕ `{c['name']}` ({RUNTIME_LABEL.get(c['kind'], c['kind'])} on {hosts.get(c['host'], {}).get('name', c['host'])})" for c in changes["added"]] +
              [f"- ➖ `{c['name']}` ({RUNTIME_LABEL.get(c['kind'], c['kind'])} on {hosts.get(c['host'], {}).get('name', c['host'])})" for c in changes["removed"]] +
              [f"- `{c['name']}` on {hosts.get(c['host'], {}).get('name', c['host'])}: {c['field']} {c['old']} → {c['new']}" for c in changes["changed"]] +
              [f"- host {x['name']}: {x.get('error') or 'kernel ' + ' → '.join(map(str, x['kernel']))}" for x in changes["hosts"]])
        lines += (ch or ["No changes."]) + [""]

    nodes, edges = ai_graph(model)
    lines += ["## AI agents & dependencies", "",
              "Solid arrows: live connections seen at collection time. Dotted: configured in the service environment.", "",
              "```mermaid", "flowchart LR"]
    for ip in sorted({comps[n].get("host", "") for n in nodes}, key=ipkey):
        members = [n for n in nodes if comps[n].get("host", "") == ip]
        title = f"{hosts[ip]['name']} ({ip})" if ip in hosts else "outside the map"
        lines.append(f'  subgraph {mermaid_id("h" + ip)}["{title}"]')
        for n in sorted(members, key=lambda n: comps[n]["name"]):
            c = comps[n]
            label = f"{c['name']}<br/><small>{RUNTIME_LABEL.get(c['kind'], c['kind'])}</small>".replace('"', "'")
            lines.append(f'    {mermaid_id(n)}["{label}"]')
        lines.append("  end")
    for x in edges:
        arrow = "-->" if "observed" in x["how"] else "-.->"
        lines.append(f'  {mermaid_id(x["src"])} {arrow}|{",".join(map(str, x["ports"]))}| {mermaid_id(x["dst"])}')
    lines += ["```", "", "## Hosts", "",
              "| Host | Role | Services | Scheduled | Containers | k8s | Notable components |", "|---|---|---|---|---|---|---|"]
    for ip in sorted(hosts, key=ipkey):
        hh = hosts[ip]
        if hh["error"]:
            lines.append(f"| {hh['name']} `{ip}` | unreachable | | | | | |")
            continue
        hc = [c for c in comps.values() if ip in c["hosts"] and not c["baseline"]]
        chips = host_chips(model, ip)
        lines.append(
            f"| **{hh['name']}** `{ip}` | {hh.get('role', '')} | {sum(1 for c in hc if c['kind'] in ('systemd', 'user-unit'))} | "
            f"{sum(1 for c in hc if c['kind'] in ('timer', 'cron'))} | "
            f"{sum(1 for c in hc if c['kind'] in ('podman', 'podman-root', 'docker'))} | {sum(1 for c in hc if c['kind'] == 'k8s')} | "
            + ", ".join(f"{'🤖 ' if ch['ai'] else ''}{ch['name']}{' ×' + str(ch['count']) if ch['count'] > 1 else ''}" for ch in chips)
            .replace("|", "/") + " |")
    lines += ["", "## AI components", "", "| Component | Host | Runtime | Category | Purpose | Schedule / ports |", "|---|---|---|---|---|---|"]
    for c in sorted((c for c in comps.values() if c["ai"] and not c["baseline"]),
                    key=lambda c: (CAT_KEYS.index(c["category"]), ipkey(c.get("host", "")), c["name"])):
        lines.append(f"| {c['name']} | {hosts.get(c.get('host', ''), {}).get('name', '')} | {RUNTIME_LABEL.get(c['kind'], c['kind'])} | "
                     f"{CAT_LABEL[c['category']]} | {c.get('purpose', '').replace('|', '/')} | "
                     f"{(c.get('schedule') or ', '.join(c.get('ports', [])[:3])).replace('|', '/')} |")
    lines += ["", "## Every component", ""]
    for ip in sorted(hosts, key=ipkey):
        hc = sorted((c for c in comps.values() if ip in c["hosts"] and not c["baseline"]),
                    key=lambda c: (CAT_KEYS.index(c["category"]), c["kind"], c["name"]))
        if not hc:
            continue
        lines += [f"<details><summary><b>{hosts[ip]['name']}</b> ({ip}): {len(hc)} components</summary>", "",
                  "| Component | Runtime | Category | Purpose | State | Schedule / ports | Image / program |", "|---|---|---|---|---|---|---|"]
        for c in hc:
            lines.append("| " + " | ".join(str(v).replace("|", "/") for v in (
                c["name"], RUNTIME_LABEL.get(c["kind"], c["kind"]), CAT_LABEL[c["category"]] + (" (AI)" if c["ai"] else ""),
                c.get("purpose", ""), c.get("state", ""), c.get("schedule") or ", ".join(c.get("ports", [])[:3]),
                f"`{c.get('image') or c.get('detail', '')}`" if (c.get("image") or c.get("detail")) else "")) + " |")
        lines += ["", "</details>", ""]
    lines += ["", f"<sub>fingerprint {model['fingerprint']} · command lines and secrets are never collected into this map; "
                  "only program/script paths, images, schedules and ports.</sub>", ""]
    return "\n".join(lines)


# ---------- main ----------

def publishable(model: dict, changes: dict) -> dict:
    keep = ("id", "host", "hosts", "kind", "name", "category", "ai", "purpose", "state", "schedule", "ports", "image",
            "detail", "user", "group", "namespace", "k8s_kind", "cluster", "replicas", "ready", "baseline", "count",
            "description", "classified_by")
    return {"generated_at": model["generated_at"], "fingerprint": model["fingerprint"],
            "change_summary": model["change_summary"], "changes": changes,
            "hosts": {ip: {k: v for k, v in h.items()} for ip, h in model["hosts"].items()},
            "clusters": model["clusters"], "edges": model["edges"],
            "components": {k: {f: c[f] for f in keep if f in c} for k, c in model["components"].items()}}


def summarize(changes: dict) -> str:
    if changes["first_run"]:
        return "first map"
    parts = []
    if changes["added"]:
        parts.append(f"+{len(changes['added'])} (" + ", ".join(c["name"] for c in changes["added"][:4]) +
                     ("…" if len(changes["added"]) > 4 else "") + ")")
    if changes["removed"]:
        parts.append(f"-{len(changes['removed'])} (" + ", ".join(c["name"] for c in changes["removed"][:4]) +
                     ("…" if len(changes["removed"]) > 4 else "") + ")")
    if changes["changed"]:
        parts.append(f"{len(changes['changed'])} changed")
    if changes["hosts"]:
        parts.append(f"{len(changes['hosts'])} host changes")
    return "; ".join(parts) or "no component changes"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-llm", action="store_true", help="rule-based labels only (plus cached LLM labels)")
    ap.add_argument("--reclassify", action="store_true", help="ignore the label cache and ask the model again")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to")
    args = ap.parse_args()

    raw = SM / "raw" / "latest.json"
    if not raw.exists():
        raise SystemExit(f"no snapshot at {raw}; run servicemap-collect first")
    snap = json.loads(raw.read_text())
    age_h = (time.time() - snap["collected_ts"]) / 3600
    if age_h > 26:
        log(f"warning: snapshot is {age_h:.0f}h old")

    agent = None if args.no_llm else Agent("servicemap-agent")
    model = build(snap)
    log(f"built map: {len(model['hosts'])} hosts, {len(model['components'])} components "
        f"({sum(1 for c in model['components'].values() if not c['baseline'])} notable), {len(model['edges'])} links")
    stats = classify(model, agent, args.reclassify)
    log(f"labels: {stats['asked']} from the model, {stats['cached']} cached, {stats['failed']} fell back to rules")
    model["generated_at"] = snap["collected_at"]
    model["fingerprint"] = fingerprint(model)

    prev_path = SM / "model-latest.json"
    prev = json.loads(prev_path.read_text()) if prev_path.exists() else None
    changes = diff(prev, model)
    model["change_summary"] = summarize(changes)
    log(f"changes: {model['change_summary']}")

    footer = (agent.footer(f"{stats['asked']} new labels, {stats['cached']} cached") if agent
              else "servicemap-agent on 192.168.1.98 · rule-based labels (--no-llm)")
    body = render(model, changes, footer)
    SITE.mkdir(parents=True, exist_ok=True)
    pub = publishable(model, changes)
    (SITE / "index.html").write_text(body)
    (SITE / "README.md").write_text(render_readme(model, changes))
    (SITE / "servicemap.json").write_text(json.dumps(pub, indent=1, default=str))
    nodes, edges = ai_graph(model)
    for theme in THEMES:
        (SITE / f"fleet-{theme}.svg").write_text(standalone(fleet_svg(model), theme))
        (SITE / f"ai-map-{theme}.svg").write_text(standalone(svg_graph(model, nodes, edges), theme))
    (SITE / "metrics").write_text(metrics(model, changes))
    save_report("servicemap", body, pub)
    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M")
    (SM / "history").mkdir(exist_ok=True)
    (SM / "history" / f"{stamp}.json").write_text(json.dumps(pub, default=str))
    prev_path.write_text(json.dumps(pub, default=str))
    log(f"site written to {SITE}")

    if not args.no_email and not changes["first_run"] and change_count(changes):
        send_mail(f"Lab service map: {model['change_summary'][:100]}", body, args.to or MAIL_TO)


if __name__ == "__main__":
    main()
