# patchwatch-agent: weekly patch and image-drift plan

Part of [mikes-agents](../README.md). Uses [lab-agents-common](../lab-agents-common/) and the inventory from
[labinventory](../labinventory/).

Every **Monday at 06:45** it emails a prioritised "what to update and why" plan for the whole lab:

- pending OS updates per host (dnf / apt)
- Rocky security advisories (RLSA) by severity, with their CVEs, merged across hosts
- hosts running an older kernel than the newest one installed (reboot pending)
- broken package repositories
- container and k8s images whose tag in the registry now points at a newer build than the one running

```
latest.json ──► per-host summary + advisories merged across hosts ─┐
              └► each running image ─HEAD /v2/<repo>/manifests/<tag>─► registry digest vs local RepoDigests
                                                                     │
                                         LiteLLM / qwen3.8-27b ◄─────┘  → priorities (critical..low) with
                                                                          commands, hosts, notes, order
                                         └─► HTML report + email
```

## Image drift check

For each image the agent asks the registry (Docker Hub, ghcr.io, quay.io, registry.k8s.io, …) for the
current manifest digest of the tag, using the anonymous Bearer-token flow and `HEAD` (doesn't count against
Docker Hub pull limits), and compares it with the `RepoDigests` / k8s `imageID` recorded by labinventory.

| Status | Meaning |
|---|---|
| current | running image = what the tag points to now |
| newer available | the tag has moved (e.g. `:latest`, `:3.6`); pull and recreate to update |
| not in public registry | registry answered 401/404: a local or private build |
| local build | `localhost/...` image |
| unknown | no digest recorded locally, or the registry check failed |

## What the model is told

Prioritise Critical/Important advisories and known-exploited issues, then internet-facing or shared services
(LiteLLM .101, Kong .100, Cloudflare ingress .99, Twingate .85), then the rest. Group hosts that need the same
thing, mention reboots after kernel updates, suggest pinning `:latest` images, and give concrete commands.
The vulnerable demo apps (crAPI, Juice Shop, VAmPI, DVGA) are intentionally vulnerable, so it notes their age
but doesn't recommend "fixing" them.

## Output

`/opt/labagents/data/reports/patchwatch/<date>.html` (priorities, repository problems, per-host table,
Critical/Important advisories, container-image table) + `.json`, `latest.html`.

First test run (2026-10-07, 3.5 min): 9 priorities. A Critical freerdp advisory on .104 came first, then
.101 (Critical + Important: curl, openssh, libxml2, sudo), the gateway hosts, the rest of the Rocky hosts and
the Pis. Broken `Noname-Artifactory` repo on .101 and .102. Images with newer builds: nginx (k3s), docker:dind,
searxng, postgres (×2), the Twingate connector.

## Files

| File | Installed at |
|---|---|
| `patchwatch.py` | `/opt/labagents/app/labagents/patchwatch.py` (in the image) |
| `patchwatch` | `/usr/local/bin/patchwatch` |
| `patchwatch.service` / `.timer` | `/etc/systemd/system/` (Mondays 06:45, `After=labinventory.service`) |

## Install

Needs [labinventory](../labinventory/) running and `PATCHWATCH_KEY` in the env file:

```bash
sudo cp patchwatch.py /opt/labagents/app/labagents/
sudo podman build -t localhost/labagents:latest -f /opt/labagents/app/Containerfile /opt/labagents/app
sudo install -m 755 patchwatch /usr/local/bin/patchwatch
sudo cp patchwatch.service patchwatch.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now patchwatch.timer
patchwatch --no-email
```

## Usage

```bash
patchwatch               # run + email
patchwatch --no-email
labinventory && patchwatch   # fresh inventory first (e.g. right after patching)
```

The agent only reads and reports. It never installs anything.
