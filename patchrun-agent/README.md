# patchrun-agent

Part of [mikes-agents](../README.md). Applies the OS security updates that [patchwatch](../patchwatch-agent/)
recommends, **with human approval**. patchwatch writes the plan; patchrun carries it out, conservatively.

## Safety model

- **Dry-run by default.** With no `--approve`, patchrun only *simulates* on every host
  (`dnf check-update --security` / `apt-get -s upgrade`) and reports what would change. Nothing is modified.
- **Approval is tied to the plan.** `--approve <token>` actually applies. The token is derived from the latest
  patchwatch report id, so an approval only matches the plan it was issued for — a newer patchwatch plan needs
  a new token. Run a dry-run to see the current token.
- **Security updates only** unless `--all`. It **never reboots** (that's [ops/lab-reboots.sh](../ops/)), but it
  reports which hosts now need one.
- The intentionally-vulnerable lab containers (crAPI/Juice Shop/VAmPI/DVGA) are never touched — this patches
  host OS packages only.

Hosts, order (least-critical first, `.98` last) and OS come from the latest labinventory. After the run the
model writes a plain-English result summary.

## Run

```bash
patchrun                       # dry-run on all hosts; prints the approval token
patchrun --approve <token>     # apply security updates to every host in the plan
patchrun --approve <token> --all --hosts 192.168.1.103,192.168.1.104
```

Not scheduled — it is run on demand (the proposal comes from patchwatch's daily 06:45 email).

## Requirements

Runs in the labagents container as root but SSHes out **as the lab user** (`PATCHRUN_SSH_USER`, default
`mcropsey`); the wrapper mounts `~/.ssh` read-only at `/root/.ssh`. Needs passwordless SSH + `sudo -n` on every
host (same as labinventory/servicemap).

## LiteLLM

Key `PATCHRUN_KEY`, alias `patchrun-agent`, opted out of `basic-safety-filter`. Used only for the post-run
summary; execution itself is deterministic. See [litellm/](../litellm/).

## Reports & Grafana

`/opt/labagents/data/reports/patchrun/`, listed at `:9440/reports/#patchrun`; metrics `mikes_patchrun_*` and
report logs via [agenthub](../agenthub/) (dashboard *Agent Lab · Agents II*).
