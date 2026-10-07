"""cvewatch-agent: match newly published CVEs against the software actually running in the lab.

1. Pulls CVEs published in the look-back window from the NVD API and recent CISA KEV additions.
2. Pre-filters them against the lab inventory (packages, container images, k8s images) by product name.
3. Groups matches by lab product and asks the model to judge each group (affected / possibly / not affected)
   using installed versions, and cross-checks Rocky security advisories that already ship a fix.
4. Emails only when something in the lab is (possibly) affected, unless --always-email.

Usage: python -m labagents.cvewatch [--hours N] [--no-email] [--always-email] [--to ADDR]
"""
import argparse
import datetime as dt
import json
import re
import time

import httpx

from .common import LAB_HOSTS, MAIL_TO, Agent, card, e, load_inventory, log, page, save_report, send_mail, table

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_GROUPS = 15

# NVD product names that differ from package / image names.
ALIASES = {
    "linux_kernel": "kernel", "linux kernel": "kernel", "linux": "kernel", "linux_linux": "kernel", "openssh": "openssh", "openssl": "openssl",
    "http_server": "httpd", "node.js": "nodejs", "postgresql": "postgres", "mongodb": "mongo",
    "kong_gateway": "kong", "kubernetes": "k8s", "ingress-nginx": "ingress-nginx", "glibc": "glibc",
    "bind": "bind", "bind 9": "bind", "sudo": "sudo", "polkit": "polkit", "systemd": "systemd",
    "docker": "docker", "moby": "docker", "containerd": "containerd", "runc": "runc", "podman": "podman",
    "python": "python3", "cpython": "python3", "git": "git", "curl": "curl", "libcurl": "curl", "xz": "xz",
    "grafana": "grafana", "loki": "loki", "prometheus": "prometheus", "alertmanager": "alertmanager",
    "jenkins": "jenkins", "litellm": "litellm", "chroma": "chromadb", "searxng": "searxng", "nginx": "nginx",
    "cadvisor": "cadvisor", "k3s": "k3s", "microk8s": "microk8s", "juice_shop": "juice-shop",
    "cloudflared": "cloudflared", "twingate": "twingate", "samba": "samba", "vim": "vim", "rsync": "rsync",
}
# Names worth matching in free-text descriptions (CVEs awaiting analysis often have no product data).
# Kept short: generic package names ("file", "less", "time") would match everything.
NOTABLE = {"openssh", "openssl", "sudo", "glibc", "systemd", "polkit", "curl", "podman", "runc", "containerd",
           "docker", "kernel", "nginx", "ingress-nginx", "httpd", "bind", "samba", "git", "xz", "python3",
           "nodejs", "postgres", "mongo", "kong", "jenkins", "grafana", "loki", "prometheus", "alertmanager",
           "litellm", "chromadb", "searxng", "cadvisor", "k3s", "microk8s", "k8s", "cloudflared", "twingate",
           "juice-shop", "vim", "rsync", "cockpit", "firewalld", "nftables", "dnsmasq", "chrony", "pam"}
DESC_PATTERNS = {"kernel": r"\bLinux kernel\b", "k8s": r"\bKubernetes\b", "httpd": r"\bApache HTTP Server\b",
                 "python3": r"\b(CPython|Python interpreter)\b", "nodejs": r"\bNode\.js\b",
                 "postgres": r"\bPostgreSQL\b", "mongo": r"\bMongoDB\b", "bind": r"\bBIND 9\b"}

SYSTEM = f"""You are a vulnerability analyst for a home lab used for API-security demos.

Lab hosts:
{LAB_HOSTS}

You get newly published CVEs that a pre-filter matched to software installed in the lab, grouped by lab
product, with the installed versions and where they run. For each GROUP decide whether the lab is exposed:
- "affected": the product matches and an installed version is in an affected range (or no range is given
  and the product clearly matches).
- "possibly": the product matches but the version or configuration can't be confirmed from the data.
- "not_affected": wrong product (name collision, e.g. a WordPress plugin that merely mentions nginx), or every
  installed version is outside the affected ranges.
Rocky/RHEL packages carry backported fixes, so an upstream version number alone is weak evidence: if a
"rocky_fix_available" advisory is listed, say so and recommend the dnf update. KEV = known exploited, rate it up.
Keep text short: this is a triage list, not an essay.

Reply with ONLY this JSON:
{{"summary": "2-3 sentences for the owner",
 "findings": [{{"product": "group product", "verdict": "affected|possibly|not_affected",
               "severity": "critical|high|medium|low", "cves": ["the CVEs in this group that matter, worst first"],
               "hosts": ["name (ip)"], "installed": "version(s)", "why": "1-2 sentences",
               "action": "concrete fix or check, empty if not affected"}}]}}
One finding per group. Order: affected, possibly, not_affected; then by severity."""


def norm(name: str) -> str:
    name = name.lower().strip()
    return ALIASES.get(name, ALIASES.get(name.replace("_", " "), name.replace("_", "-")))


def image_product(image: str) -> str:
    repo = image.split("@")[0].rsplit(":", 1)[0] if ":" in image.split("/")[-1] else image.split("@")[0]
    return norm(repo.split("/")[-1])


def build_index(inv: dict) -> dict:
    """product -> list of {host, kind, name, version} across the lab."""
    index: dict = {}

    def add(product, entry):
        index.setdefault(product, []).append(entry)

    for ip, h in inv["hosts"].items():
        if h.get("error"):
            continue
        who = f"{h['name']} ({ip})"
        for pkg, ver in h.get("packages", {}).items():
            entry = {"host": who, "kind": "package", "name": pkg, "version": ver}
            add(norm(pkg), entry)
            base = re.split(r"[-.]", pkg)[0]  # openssh-server -> openssh, containerd.io -> containerd
            if base != pkg and base in NOTABLE and base != "kernel":
                add(base, entry)
        if h.get("kernel"):
            add("kernel", {"host": who, "kind": "kernel", "name": "running kernel", "version": h["kernel"]})
        for c in h.get("containers", []):
            tag = c["image"].rsplit(":", 1)[1] if ":" in c["image"].split("/")[-1] else "latest"
            add(image_product(c["image"]), {"host": who, "kind": "container", "name": c["name"],
                                            "version": f"{c['image']} (tag {tag}, built {c.get('created', '?')[:10]})"})
        for k in h.get("k8s", []):
            add(image_product(k["image"]), {"host": who, "kind": "k8s pod", "name": k["pod"], "version": k["image"]})
        if h.get("k8s"):
            add("k8s", {"host": who, "kind": "kubernetes node", "name": "k3s" if ip.endswith(".99") else "microk8s",
                        "version": "see host"})
    return index


def fetch_nvd(client: httpx.Client, hours: int) -> list:
    end = dt.datetime.now(dt.timezone.utc)
    start = end - dt.timedelta(hours=hours)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    out, idx = [], 0
    while True:
        for attempt in range(4):
            r = client.get(NVD, params={"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
                                        "resultsPerPage": 2000, "startIndex": idx})
            if r.status_code in (403, 429, 503):  # NVD rate limit without an API key: back off
                time.sleep(10 * (attempt + 1))
                continue
            r.raise_for_status()
            break
        else:
            r.raise_for_status()
        d = r.json()
        out += [v["cve"] for v in d.get("vulnerabilities", [])]
        idx += d.get("resultsPerPage", 0)
        if idx >= d.get("totalResults", 0) or not d.get("resultsPerPage"):
            return out
        time.sleep(6)


def cve_products(cve: dict) -> list:
    """(vendor, product, versions-text) from the new 'affected' block or legacy CPE configurations."""
    prods = []
    for a in cve.get("affected") or []:
        for ad in a.get("affectedData") or []:
            vers = []
            for v in ad.get("versions") or []:
                if v.get("status") == "affected":
                    rng = v.get("version", "")
                    for k, sym in (("lessThan", "<"), ("lessThanOrEqual", "<=")):
                        if v.get(k):
                            rng = f"{rng}..{sym}{v[k]}" if rng not in ("", "0", "*") else f"{sym}{v[k]}"
                    vers.append(rng)
            prods.append((ad.get("vendor") or "", ad.get("product") or ad.get("packageName") or "", ", ".join(vers[:4])))
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    p = m["criteria"].split(":")
                    rng = "".join(f"{sym}{m[k]} " for k, sym in (("versionStartIncluding", ">="), ("versionEndExcluding", "<"),
                                                                  ("versionEndIncluding", "<=")) if m.get(k))
                    prods.append((p[3], p[4], (rng or p[5]).strip()))
    return prods


def cvss(cve: dict) -> tuple[float, str]:
    best = (0.0, "")
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in cve.get("metrics", {}).get(key, []):
            d = m["cvssData"]
            if d.get("baseScore", 0) > best[0]:
                best = (d["baseScore"], d.get("baseSeverity", ""))
    return best


def installs_summary(entries: list) -> list:
    """Compress install entries to "name version: hosts" lines."""
    by_ver: dict = {}
    for i in entries:
        by_ver.setdefault(f"{i['kind']} {i['name']} {i['version']}", []).append(i["host"].split(" ")[0])
    return [f"{k}: {', '.join(sorted(set(v)))}" for k, v in sorted(by_ver.items())][:10]


def match(cves: list, kev: list, index: dict, inv: dict) -> tuple[list, dict]:
    """Return candidate groups, one per lab product, each holding its worst CVEs."""
    kev_ids = {v["cveID"]: v for v in kev}
    fixes: dict = {}
    for ip, h in inv["hosts"].items():
        for s in h.get("security_cves", []):
            fixes.setdefault(s["cve"], set()).add(f"{h['name']}: {s['package']} ({s['severity']})")
    groups: dict = {}

    def add(product: str, item: dict):
        groups.setdefault(product, []).append(item)

    for cve in cves:
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        prods = cve_products(cve)
        hits = {name for vendor, product, _ in prods
                for name in (norm(product), norm(f"{vendor}_{product}")) if name in index}
        via = "product data"
        if not hits and not prods:  # free-text match only when NVD has no product data at all
            hits = {name for name in NOTABLE & index.keys()
                    if re.search(DESC_PATTERNS.get(name, rf"\b{re.escape(name)}\b"), desc, re.I)}
            via = "description only"
        score, _ = cvss(cve)
        for name in hits:
            add(name, {"cve": cve["id"], "cvss": score, "kev": cve["id"] in kev_ids, "via": via,
                       "affected": [f"{v} {p} {r}".strip() for v, p, r in prods][:3], "description": desc[:300],
                       "rocky_fix_available": sorted(fixes.get(cve["id"], []))[:4]})
    # KEV additions outside this NVD window (older CVEs newly added to KEV)
    seen = {i["cve"] for items in groups.values() for i in items}
    for cid, v in kev_ids.items():
        name = next((n for n in (norm(v["product"]), norm(v["vendorProject"])) if n in index), None)
        if cid not in seen and name:
            add(name, {"cve": cid, "cvss": None, "kev": True, "via": "KEV product",
                       "affected": [f"{v['vendorProject']} {v['product']}"],
                       "description": f"{v['vulnerabilityName']}: {v['shortDescription']}"[:300],
                       "rocky_fix_available": sorted(fixes.get(cid, []))[:4]})
    out = []
    for product, items in groups.items():
        items.sort(key=lambda i: (-i["kev"], -bool(i["rocky_fix_available"]), -(i["cvss"] or 0)))
        out.append({"product": product, "total_cves": len(items), "kev": any(i["kev"] for i in items),
                    "max_cvss": max((i["cvss"] or 0) for i in items), "lab_installs": installs_summary(index[product]),
                    "cves": items[:6]})
    out.sort(key=lambda g: (-g["kev"], -g["max_cvss"], -g["total_cves"]))
    stats = {"cves_matched": sum(g["total_cves"] for g in out), "groups_dropped": max(0, len(out) - MAX_GROUPS)}
    return out[:MAX_GROUPS], stats


def render(result: dict, groups: list, stats: dict, hours: int, n_cves: int, n_kev: int, footer: str) -> str:
    by_product = {g["product"]: g for g in groups}
    verdicts: dict = {"affected": [], "possibly": [], "not_affected": []}
    for f in result.get("findings", []):
        verdicts.setdefault(f.get("verdict", "possibly"), []).append(f)
    parts = [f'<p>{e(result.get("summary"))}</p>']
    for verdict, label in (("affected", "Affected"), ("possibly", "Possibly affected")):
        if not verdicts.get(verdict):
            continue
        parts.append(f"<h3>{label} ({len(verdicts[verdict])})</h3>")
        for f in verdicts[verdict]:
            g = by_product.get(f.get("product"), {})
            cves = f.get("cves") or [i["cve"] for i in g.get("cves", [])]
            meta = " · ".join(filter(None, [f"max CVSS {g['max_cvss']}" if g.get("max_cvss") else "",
                                            "CISA KEV" if g.get("kev") else "",
                                            f"{g.get('total_cves', len(cves))} CVEs", ", ".join(f.get("hosts", []))]))
            links = " ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}">{e(c)}</a>' for c in cves[:8])
            body = (f'<div>{e(f.get("why"))}</div><div style="font-size:13px;color:#4a5568">Installed: '
                    f'{e(f.get("installed"))}</div>'
                    + (f'<div style="margin-top:4px"><b>Action:</b> {e(f["action"])}</div>' if f.get("action") else "")
                    + f'<div style="font-size:12px;margin-top:4px">{links}</div>')
            parts.append(card(f.get("severity", "medium"), str(f.get("product", "")), body, meta))
    if verdicts.get("not_affected"):
        parts.append("<h3>Checked, not affected</h3>" + table(
            ["Product", "CVEs", "Why not"],
            [[e(f.get("product")), e(", ".join((f.get("cves") or [])[:3])), e(f.get("why"))]
             for f in verdicts["not_affected"]]))
    parts.append(f'<p style="font-size:13px;color:#4a5568">Window: last {hours}h · {n_cves} new CVEs on NVD, '
                 f'{n_kev} recent KEV additions · {stats["cves_matched"]} CVEs matched {len(groups)} lab products</p>')
    return page(f"CVE watch: {dt.datetime.now():%a %b %d}", "".join(parts), footer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--always-email", action="store_true", help="email even when nothing is affected")
    ap.add_argument("--to", default=MAIL_TO)
    args = ap.parse_args()

    inv, inv_warn = load_inventory()
    index = build_index(inv)
    with httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": "cvewatch-agent/1.0"}) as client:
        cves = fetch_nvd(client, args.hours)
        kev_all = client.get(KEV, headers={"User-Agent": "curl/7.76.1"}).json()["vulnerabilities"]
    since = (dt.date.today() - dt.timedelta(days=max(2, args.hours // 24 + 1))).isoformat()
    kev = [v for v in kev_all if v.get("dateAdded", "") >= since]
    cands, stats = match(cves, kev, index, inv)
    log(f"{len(cves)} new CVEs, {len(kev)} KEV additions -> {stats['cves_matched']} matched "
        f"{len(cands)} lab products: {', '.join(g['product'] for g in cands)}")

    agent = Agent("cvewatch-agent")
    if cands:
        result = agent.ask_json(SYSTEM, "Candidate groups:\n" + json.dumps(cands, indent=1))
    else:
        result = {"summary": "No newly published CVE matched software running in the lab.", "findings": []}
    hits = [f for f in result.get("findings", []) if f.get("verdict") in ("affected", "possibly")]
    log(f"{len(hits)} affected/possibly, {len(result.get('findings', [])) - len(hits)} not affected")

    footer = agent.footer(f"inventory {inv['collected_at']}" + (f" ({inv_warn})" if inv_warn else ""))
    body = render(result, cands, stats, args.hours, len(cves), len(kev), footer)
    save_report("cvewatch", body, {"result": result, "groups": cands, "stats": stats})
    if args.no_email:
        return
    if hits or args.always_email:
        worst = next((f for f in hits if f.get("verdict") == "affected"), hits[0] if hits else None)
        subject = (f"CVE watch: {len(hits)} may affect the lab" + (f" ({worst.get('product', '')})" if worst else "")
                   if hits else "CVE watch: nothing affects the lab today")
        send_mail(subject, body, args.to)
    else:
        log("nothing affects the lab; no email (use --always-email to send anyway)")


if __name__ == "__main__":
    main()
