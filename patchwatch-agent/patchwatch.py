"""patchwatch-agent: weekly "what to update and why" report for the lab.

Uses the lab inventory (pending dnf/apt updates, Rocky security advisories with CVEs, reboot-needed flags,
broken repos) and checks every running container / k8s image against its registry to see whether the
tag now points at a newer build. The model turns that into a prioritised patch plan.

Usage: python -m labagents.patchwatch [--no-email] [--to ADDR]
"""
import argparse
import datetime as dt
import json
import re
from collections import defaultdict

import httpx

from .common import LAB_HOSTS, MAIL_TO, Agent, card, e, load_inventory, log, page, save_report, send_mail, table

SEV_RANK = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3}
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json"])

SYSTEM = f"""You are the patch manager for a home lab used for API-security demos. Write this week's patch plan.

Lab hosts:
{LAB_HOSTS}

You get, per host: pending OS updates, Rocky security advisories (with severity and CVE counts), whether a
reboot is pending, broken package repos; and for container/k8s images whether the registry has a newer build
of the same tag. Prioritise: critical/important security advisories and known-exploited issues first,
internet-facing or shared services next (LiteLLM .101, Kong .100, Cloudflare ingress .99, Twingate .85),
then the rest. Group hosts that need the same thing. Mention reboots after kernel updates. For containers on
":latest"-style tags suggest pinning. Note risks (e.g. .101 is RAM-tight, k3s/microk8s nodes, the Noname
sensors) and suggest an order. Be concrete: give the commands (dnf update / apt upgrade / podman pull + recreate).
The vulnerable-app containers (crAPI, Juice Shop, VAmPI, DVGA) are intentionally vulnerable: don't recommend
"fixing" them, only note if they're very old.

Reply with ONLY this JSON:
{{"headline": "one sentence",
 "summary": "3-4 sentences",
 "priorities": [{{"priority": "critical|high|medium|low", "title": "...", "hosts": ["name (ip)"],
                 "why": "CVE/advisory/age reasons", "commands": "shell commands", "notes": "risks / reboot / order"}}],
 "containers": [{{"host": "...", "container": "...", "image": "...", "status": "newer available|current|unknown",
                 "advice": "short"}}],
 "repo_problems": ["..."]}}"""


# ---------- registry checks ----------

def parse_ref(ref: str) -> tuple[str, str, str]:
    """image ref -> (registry host, repository, tag)."""
    ref = ref.split("@")[0]
    name, tag = (ref.rsplit(":", 1) if ":" in ref.split("/")[-1] else (ref, "latest"))
    parts = name.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry, repo = parts[0], "/".join(parts[1:])
    else:
        registry, repo = "docker.io", name
    if registry == "docker.io":
        registry = "registry-1.docker.io"
        if "/" not in repo:
            repo = f"library/{repo}"
    return registry, repo, tag


def remote_digest(client: httpx.Client, ref: str) -> str:
    registry, repo, tag = parse_ref(ref)
    url = f"https://{registry}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": MANIFEST_ACCEPT}
    r = client.head(url, headers=headers)
    if r.status_code == 401 and "bearer" in r.headers.get("www-authenticate", "").lower():
        params = dict(re.findall(r'(\w+)="([^"]*)"', r.headers["www-authenticate"]))
        realm = params.pop("realm")
        params.setdefault("scope", f"repository:{repo}:pull")
        token = client.get(realm, params=params).json()
        headers["Authorization"] = f"Bearer {token.get('token') or token.get('access_token')}"
        r = client.head(url, headers=headers)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    return r.headers.get("docker-content-digest", "")


def check_images(inv: dict) -> list:
    """One row per running container / unique k8s image with registry status."""
    rows, seen_k8s = [], set()
    for ip, h in inv["hosts"].items():
        who = f"{h['name']} ({ip})"
        for c in h.get("containers", []):
            rows.append({"host": who, "container": c["name"], "image": c["image"], "created": c.get("created", "")[:10],
                         "local_digests": [d.split("@")[-1] for d in c.get("repo_digests", [])]})
        for k in h.get("k8s", []):
            if k["image"].startswith("sha256:") or (k["image"], k["image_id"]) in seen_k8s:
                continue
            seen_k8s.add((k["image"], k["image_id"]))
            rows.append({"host": who, "container": f"k8s {k['pod'].rsplit('-', 2)[0]}", "image": k["image"],
                         "created": "", "local_digests": [k["image_id"].split("@")[-1]] if "@" in k["image_id"] else []})
    cache: dict = {}
    with httpx.Client(timeout=20, follow_redirects=True) as client:
        for row in rows:
            ref = row["image"]
            if ref.startswith(("localhost/", "sha256:")):
                row["status"], row["detail"] = "local build", "built locally; not in a registry"
                continue
            if not row["local_digests"]:
                row["status"], row["detail"] = "unknown", "no repo digest recorded locally"
                continue
            if ref not in cache:
                try:
                    cache[ref] = remote_digest(client, ref)
                except Exception as ex:
                    cache[ref] = f"error: {ex}"
            remote = cache[ref]
            if remote in ("error: HTTP 401", "error: HTTP 404"):  # Docker Hub answers 401 for repos that don't exist
                row["status"], row["detail"] = "not in public registry", "local or private build; can't check"
            elif remote.startswith("error"):
                row["status"], row["detail"] = "unknown", remote
            elif remote in row["local_digests"]:
                row["status"], row["detail"] = "current", "matches registry"
            else:
                row["status"], row["detail"] = "newer available", f"registry tag now {remote[:19]}"
    return rows


# ---------- summarising the inventory for the model ----------

def host_summaries(inv: dict) -> tuple[list, dict]:
    hosts, advisories = [], defaultdict(lambda: {"severity": "", "packages": set(), "hosts": set(), "cves": set()})
    for ip, h in inv["hosts"].items():
        who = f"{h['name']} ({ip})"
        if h.get("error"):
            hosts.append({"host": who, "error": h["error"]})
            continue
        cves_by_pkg = defaultdict(set)
        for c in h.get("security_cves", []):
            cves_by_pkg[c["package"]].add(c["cve"])
        for s in h.get("security", []):
            a = advisories[s["advisory"]]
            a["severity"] = s["severity"]
            a["packages"].add(re.sub(r"-\d.*$", "", s["package"]))
            a["hosts"].add(who)
            a["cves"] |= cves_by_pkg.get(s["package"], set())
        sev_count = defaultdict(int)
        for severity in {s["advisory"]: s["severity"] for s in h.get("security", [])}.values():
            sev_count[severity] += 1
        ups = h.get("updates", [])
        hosts.append({
            "host": who, "os": h.get("os"), "kernel": h.get("kernel"), "booted": h.get("booted"),
            "pending_updates": len(ups),
            "security_advisories": dict(sev_count),
            "apt_security_updates": [f"{u['name']} {u['installed']} -> {u['version']}" for u in ups if u.get("security")],
            "kernel_update_pending": any(u["name"].startswith(("kernel", "linux-image")) for u in ups),
            "reboot_required": h.get("reboot_required"),
            "repo_errors": h.get("update_errors", [])[:3],
            "notable_updates": [f"{u['name']} {u.get('installed', '')} -> {u['version']}" for u in ups
                                if re.match(r"(kernel|openssh|openssl|glibc|sudo|systemd|podman|runc|containerd|"
                                            r"docker|bind|curl|python3|nginx|polkit)", u["name"])][:15],
        })
    adv_list = sorted(({"advisory": k, "severity": v["severity"], "packages": sorted(v["packages"])[:6],
                        "hosts": sorted(v["hosts"]), "cve_count": len(v["cves"]), "cves": sorted(v["cves"])[:8]}
                       for k, v in advisories.items() if k.startswith(("RLSA", "RHSA", "ALSA"))),
                      key=lambda a: (SEV_RANK.get(a["severity"], 9), -len(a["hosts"])))
    return hosts, adv_list


def render(result: dict, hosts: list, advs: list, images: list, footer: str) -> str:
    parts = [f'<p style="font-size:16px"><b>{e(result.get("headline"))}</b></p><p>{e(result.get("summary"))}</p>']
    for p in result.get("priorities", []):
        body = (f'<div>{e(p.get("why"))}</div>'
                + (f'<pre style="background:#f7fafc;padding:6px 8px;font-size:12px;white-space:pre-wrap">'
                   f'{e(p["commands"])}</pre>' if p.get("commands") else "")
                + (f'<div style="font-size:13px;color:#4a5568">{e(p["notes"])}</div>' if p.get("notes") else ""))
        parts.append(card(p.get("priority", "medium"), p.get("title", ""), body, ", ".join(p.get("hosts", []))))
    if result.get("repo_problems"):
        parts.append("<h3>Repository problems</h3><ul>" + "".join(f"<li>{e(r)}</li>" for r in result["repo_problems"]) + "</ul>")
    parts.append("<h3>Hosts</h3>" + table(
        ["Host", "Pending", "Security advisories", "Reboot", "Booted"],
        [[e(h["host"]), e(h.get("pending_updates", h.get("error", ""))),
          e(", ".join(f"{v} {k}" for k, v in sorted(h.get("security_advisories", {}).items(),
                                                    key=lambda kv: SEV_RANK.get(kv[0], 9)))
            or (f"{len(h['apt_security_updates'])} apt security" if h.get("apt_security_updates") else "-")),
          "yes" if h.get("reboot_required") else ("?" if h.get("reboot_required") is None else "no"),
          e((h.get("booted") or "")[:10])] for h in hosts]))
    top = [a for a in advs if a["severity"] in ("Critical", "Important")][:15]
    if top:
        parts.append("<h3>Critical / Important advisories</h3>" + table(
            ["Advisory", "Severity", "Packages", "Hosts", "CVEs"],
            [[e(a["advisory"]), e(a["severity"]), e(", ".join(a["packages"])), e(len(a["hosts"])),
              e(a["cve_count"])] for a in top]))
    color = {"newer available": "#d9480f", "current": "#2f855a"}
    parts.append("<h3>Container images</h3>" + table(
        ["Host", "Container", "Image", "Built", "Registry"],
        [[e(i["host"].split(" ")[0]), e(i["container"]), e(i["image"]), e(i.get("created")),
          f'<span style="color:{color.get(i["status"], "#4a5568")}">{e(i["status"])}</span>'] for i in images]))
    return page(f"Patch plan: week of {dt.date.today():%b %d, %Y}", "".join(parts), footer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--to", default=MAIL_TO)
    args = ap.parse_args()

    inv, inv_warn = load_inventory()
    hosts, advs = host_summaries(inv)
    images = check_images(inv)
    counts = {s: sum(1 for i in images if i["status"] == s) for s in {i["status"] for i in images}}
    log(f"{len(hosts)} hosts, {len(advs)} advisories, images: {counts}")

    agent = Agent("patchwatch-agent")
    payload = {"hosts": hosts, "security_advisories": advs[:60],
               "images": [{k: v for k, v in i.items() if k != "local_digests"} for i in images]}
    result = agent.ask_json(SYSTEM, json.dumps(payload, indent=1))
    log(f"{len(result.get('priorities', []))} priorities")

    footer = agent.footer(f"inventory {inv['collected_at']}" + (f" ({inv_warn})" if inv_warn else ""))
    body = render(result, hosts, advs, images, footer)
    save_report("patchwatch", body, {"result": result, "hosts": hosts, "advisories": advs, "images": images})
    if not args.no_email:
        send_mail(f"Patch plan {dt.date.today()}: {result.get('headline', '')[:90]}", body, args.to)


if __name__ == "__main__":
    main()
