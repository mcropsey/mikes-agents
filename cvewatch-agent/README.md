# cvewatch-agent: CVE-to-lab matcher

Part of [mikes-agents](../README.md). Uses [lab-agents-common](../lab-agents-common/) and the inventory from
[labinventory](../labinventory/).

Every day at **06:30** it takes the CVEs published on NVD in the last 24 h (often 400+) plus new CISA KEV
entries and works out which ones touch software **actually running in the lab**. It **emails only when
something is affected or possibly affected**; quiet days produce a saved report and no email.

```
NVD API (pubStartDate..now) ─┐
CISA KEV (recent additions) ─┼─► pre-filter by product name ─► group by lab product ─► LiteLLM / qwen3.8-27b
latest.json inventory ───────┘     (packages, containers,        (worst 6 CVEs per        judges each group:
  + Rocky advisories (CVE→fix)      k8s images, kernel)           product, ≤15 groups)    affected / possibly /
                                                                                           not_affected
                                              └─► HTML report (+ email if anything is affected)
```

## Matching

1. **Lab product index** built from the inventory: every rpm/dpkg package name, base names of notable
   packages (`openssh-server` → `openssh`, `containerd.io` → `containerd`), each running container image
   and k8s pod image (`docker.io/library/kong:3.6` → `kong`), the running kernel, and the k3s/microk8s nodes.
2. **CVE products** from NVD's `affected` block (vendor/product/version ranges) or legacy CPE configurations,
   normalised with an alias table (`linux` → `kernel`, `kubernetes` → `k8s`, `moby` → `docker`, …).
3. **Description match** (e.g. "Linux kernel", "OpenSSH", "Kubernetes") is used **only when NVD has no
   product data at all**, and only for a short list of notable names, to avoid false hits such as "git"
   matching Gitea.
4. **Fix cross-check:** if a Rocky host's `dnf updateinfo --with-cve` lists the CVE, the group carries
   `rocky_fix_available` and the model recommends the dnf update.
5. Groups are sorted by KEV, then max CVSS. The model gets ≤15 groups (~8 KB of JSON).

The model is told that Rocky packages carry backported fixes, so an upstream version number alone is weak
evidence.

## Output

`/opt/labagents/data/reports/cvewatch/<date>.html` + `.json` (verdicts plus the candidate groups),
`latest.html`. Email subject: `CVE watch: 3 may affect the lab (docker)`.

First test run (2026-10-07): 471 new CVEs → 34 matched 4 lab products → in 77 s: Docker Engine on rasp5
(older than the 29.8.2 fix), OpenSSH 9.6p1 on the Ubuntu Pis, ImageMagick on rasp5 (affected); two kernel
CVEs "possibly" (ranges given as commit hashes).

## Files

| File | Installed at |
|---|---|
| `cvewatch.py` | `/opt/labagents/app/labagents/cvewatch.py` (in the image) |
| `cvewatch` | `/usr/local/bin/cvewatch` |
| `cvewatch.service` / `.timer` | `/etc/systemd/system/` (06:30 daily, `After=labinventory.service`) |

## Install

Needs [labinventory](../labinventory/) running and `CVEWATCH_KEY` in the env file:

```bash
sudo cp cvewatch.py /opt/labagents/app/labagents/
sudo podman build -t localhost/labagents:latest -f /opt/labagents/app/Containerfile /opt/labagents/app
sudo install -m 755 cvewatch /usr/local/bin/cvewatch
sudo cp cvewatch.service cvewatch.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now cvewatch.timer
cvewatch --no-email
```

## Usage

```bash
cvewatch                   # run; email only if something is (possibly) affected
cvewatch --always-email    # email even on a quiet day
cvewatch --hours 72        # catch up after a weekend
cvewatch --no-email
```

## Tuning

- `ALIASES` maps NVD product names onto lab names, and `NOTABLE` / `DESC_PATTERNS` control description
  matching. Add a line when a product the lab runs is missed (e.g. a new container image).
- `MAX_GROUPS` (15) and 6 CVEs per group keep the prompt small. An earlier version that sent 50 separate CVEs
  ran out of the 24k-token output budget.
- The NVD API is used without a key (5 requests / 30 s). One page of 2000 results covers a normal day; the
  code backs off on 403/429/503.
