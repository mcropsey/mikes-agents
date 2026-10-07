#!/bin/bash
# One-at-a-time reboots after the 2026-10-07 security patching. Runs on .98 as mcropsey (lab SSH key).
# For each host: skip if already on its newest kernel; record running containers; reboot; wait for SSH;
# check failed units and that every container is running again; only then continue.
# Stops the whole run if a host doesn't come back. .98 (this host) goes last.
# DRY_RUN=1 only checks and logs.
ORDER="103 104 105 102 100 99 101 98"
LOG=/home/mcropsey/patching/2026-10-07/reboots.log
SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=5"
log(){ echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

needs_reboot(){  # 0 = needs reboot
  $SSH 192.168.1.$1 'l=$(rpm -q --last kernel-core | head -1 | awk "{print \$1}" | sed "s/^kernel-core-//"); [ "$l" != "$(uname -r)" ]'
}
containers(){  # names of running containers (rootful podman + docker), sorted
  $SSH 192.168.1.$1 '{ sudo -n podman ps --format "{{.Names}}"; command -v docker >/dev/null && ! docker --version | grep -qi podman && sudo -n docker ps --format "{{.Names}}"; } 2>/dev/null | sort -u'
}

log "=== reboot run start (DRY_RUN=${DRY_RUN:-0})"
for h in $ORDER; do
  ip=192.168.1.$h
  if ! needs_reboot $h; then log "$ip: already on newest kernel, skip"; continue; fi
  before=$(containers $h | tr '\n' ' ')
  log "$ip: needs reboot; running containers: ${before:-none}"
  [ "${DRY_RUN:-0}" = 1 ] && continue
  if [ "$h" = 98 ]; then
    log "$ip: rebooting this host now (last in the run); labwatch at 06:15 reports on it"
    sudo -n systemctl reboot
    exit 0
  fi
  boot_before=$($SSH $ip 'cat /proc/sys/kernel/random/boot_id')
  $SSH $ip 'sudo -n systemctl reboot' >/dev/null 2>&1
  up=0
  for i in $(seq 1 90); do  # up to 15 min
    sleep 10
    b=$($SSH $ip 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null)
    if [ -n "$b" ] && [ "$b" != "$boot_before" ]; then up=1; break; fi
  done
  if [ $up != 1 ]; then log "$ip: DID NOT COME BACK within 15 min - stopping the run"; exit 1; fi
  log "$ip: back up on $($SSH $ip 'uname -r')"
  for i in $(seq 1 30); do  # wait up to 10 min for every container that was running before
    sleep 20
    after=$(containers $h | tr '\n' ' ')
    missing=$(comm -23 <(echo "$before" | tr ' ' '\n' | grep . | sort) <(echo "$after" | tr ' ' '\n' | grep . | sort) | tr '\n' ' ')
    [ -z "$missing" ] && break
  done
  failed=$($SSH $ip 'systemctl --failed --no-legend --plain | awk "{print \$1}" | tr "\n" " "')
  log "$ip: failed units: ${failed:-none}; containers missing: ${missing:-none}"
  if [ -n "$missing" ]; then log "$ip: containers did not come back - stopping the run so you can look"; exit 1; fi
done
log "=== reboot run done"
