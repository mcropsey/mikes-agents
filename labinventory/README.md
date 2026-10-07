# labinventory: lab software inventory collector

Part of [mikes-agents](../README.md). **Not an LLM agent:** a plain collector that feeds
[cvewatch-agent](../cvewatch-agent/) and [patchwatch-agent](../patchwatch-agent/).

Runs daily at **05:30** on .98 as user `mcropsey`. It needs that user's SSH key, so it runs on the host rather
than in a container, using only the Python 3.9 standard library. It visits every host in `hosts.conf`
(6 at a time) and takes about 25 s for the 11 hosts.

```
.98 labinventory.py ──ssh (BatchMode) + sudo -n──► each host in hosts.conf
      │                runs one bash script on stdin, prints "@@@ <section>" blocks
      ▼
/opt/labagents/data/inventory/YYYY-MM-DD_HHMM.json  +  latest.json
```

## What it collects per host

| Section | Rocky (rpm) | Ubuntu (dpkg) |
|---|---|---|
| OS, kernel, boot time | `/etc/os-release`, `uname -r`, `uptime -s` | same |
| Installed packages | `rpm -qa` (name, epoch:version-release) | `dpkg-query -W` |
| Pending updates | `dnf check-update` (skips unreachable repos) | `apt-get update` + `apt list --upgradable` |
| Repo problems | dnf `Failed to download metadata` / `Ignoring repositories` lines | `apt-get update` E:/W: lines |
| Security advisories | `dnf updateinfo list --security` (+ `--with-cve` for CVE ids) | `-security` pocket updates |
| Reboot needed | `needs-restarting -r`, or newest installed kernel ≠ running kernel | `/var/run/reboot-required` |
| Containers | rootless podman, rootful podman, docker (skipped if it is the podman shim): name, image, image id, repo digests, created | same |
| Kubernetes pods | `k3s kubectl` / `microk8s kubectl get pods -A`: image + imageID (digest) | same |

`.77` (rk3) and `.78` (rk4) are reserved by the owner and are left out of `hosts.conf`.

## Files

| File | Installed at |
|---|---|
| `labinventory.py` | `/opt/labagents/app/labinventory.py` (755) |
| `hosts.conf` | `/opt/labagents/hosts.conf`: `<ip> <name>` per line |
| `labinventory` | `/usr/local/bin/labinventory` (wrapper: re-runs itself as mcropsey if started as root) |
| `labinventory.service` / `.timer` | `/etc/systemd/system/` (`User=mcropsey`, 05:30 daily) |

## Install

```bash
sudo mkdir -p /opt/labagents/app /opt/labagents/data && sudo chown mcropsey: /opt/labagents/data
sudo install -m 755 labinventory.py /opt/labagents/app/labinventory.py
sudo install -m 644 hosts.conf /opt/labagents/hosts.conf
sudo install -m 755 labinventory /usr/local/bin/labinventory
sudo cp labinventory.service labinventory.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now labinventory.timer
labinventory              # test: prints one line per host
```

Requirements: passwordless SSH from mcropsey@.98 to each host, and `sudo -n` on each (dnf/apt, podman, docker,
k3s/microk8s need root).

## Usage

```bash
labinventory                       # all hosts -> latest.json
labinventory --only 192.168.1.101  # one host -> a *-partial.json (latest.json untouched)
```

Example output:

```
192.168.1.101   hv-rocky-linux-4   8.5s  1266 pkgs, 63 updates, 60 sec advisories, 15 containers, 0 k8s images
192.168.1.75    rk1                3.8s  661 pkgs, 2 updates, 0 sec advisories, 0 containers, 10 k8s images
saved /opt/labagents/data/inventory/2026-10-07_1430.json; 11/11 hosts ok
```

A host that can't be reached is recorded with an `error` field; the rest of the inventory is still written.
The consumers warn when `latest.json` is more than 72 h old.

## Notes

- `sudo` doesn't search `/usr/local/bin`, so k3s is called by its full path (`$(command -v k3s)`).
- With `-q`, dnf hides the "skipping repo" warning, so `check-update` runs without `-q` to catch broken repos.
- `dnf check-update` refreshes repo metadata, which is the slowest part (~5-15 s per host).
