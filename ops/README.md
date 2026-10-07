# ops: one-off lab maintenance scripts

Part of [mikes-agents](../README.md). These are helper scripts used during maintenance, not agents.

| Script | What it does |
|---|---|
| `lab-reboots.sh` | Reboots the Rocky hosts one at a time after patching (order .103 → .104 → .105 → .102 → .100 → .99 → .101 → .98). Skips hosts already on their newest kernel. Before each reboot it records the running containers; afterwards it waits for SSH, then up to 10 min for every container to be running again, and logs failed units. Stops the whole run if a host or its containers don't come back. `.98` (where it runs) reboots last. `DRY_RUN=1` only checks and logs. |

Used for the 2026-10-07 security patching, scheduled on .98 as a transient systemd timer:

```bash
sudo systemd-run --uid=mcropsey --setenv=HOME=/home/mcropsey --unit=lab-reboots \
  --on-calendar="2026-10-07 22:05:00 America/Chicago" /bin/bash /home/mcropsey/patching/lab-reboots.sh
```

Needs passwordless SSH + `sudo -n` from mcropsey@.98 to each host. Log: `~/patching/<date>/reboots.log`.
The patching itself was done by hand (`dnf update --security`, apt `-security` pocket); patchwatch only reports.
