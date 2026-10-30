#!/usr/bin/env bash
# Idle watchdog for the minip2p bench instance, run every minute as root by
# minip2p-bench-watchdog.timer. Powers the instance off (shutdown behaviour
# `stop`) when either:
#   - it has been up 10 minutes, the `bench-lease-until` tag has expired, and
#     no Runner.Worker has existed for 2 minutes; or
#   - the oldest Runner.Worker is older than 120 minutes (a stuck job; the
#     bench job's own timeout is 90 minutes).
# The lease, not the idle limit, covers a queued job's wait for the runner
# after a start, so the idle limit only has to bridge a job's end; the uptime
# floor keeps a hand-started instance (no lease) up long enough to log in.
# Cloud-init's first-boot setup counts as busy for up to an hour.
# Decisions go to the journal: `journalctl -u minip2p-bench-watchdog`.
set -euo pipefail

idle_file=/run/minip2p-bench-idle-since
setup_marker=/run/minip2p-bench-setup
min_uptime=600
idle_limit=120
max_lease_ahead=1800
max_job_age=7200

now=$(date +%s)
uptime=$(cut -d. -f1 /proc/uptime)

# The lease tag via IMDSv2 instance-metadata tags. A missing, malformed, or
# implausibly distant value counts as expired, so no tag value pins the
# instance on.
lease=0
token=$(curl -sf -m 5 -X PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' || true)
if [[ -n "$token" ]]; then
  value=$(curl -sf -m 5 -H "X-aws-ec2-metadata-token: $token" \
    http://169.254.169.254/latest/meta-data/tags/instance/bench-lease-until || true)
  if [[ "$value" =~ ^[0-9]{1,12}$ ]] && ((value <= now + max_lease_ahead)); then
    lease=$value
  fi
fi

if [[ -f "$setup_marker" ]] && ((now - $(stat -c %Y "$setup_marker") < 3600)); then
  rm -f "$idle_file"
  echo "first-boot setup running"
  exit 0
fi

oldest=$(pgrep -o -x Runner.Worker || true)
if [[ -n "$oldest" ]]; then
  rm -f "$idle_file"
  age=$(ps -o etimes= -p "$oldest" | tr -d ' ')
  if [[ -n "$age" ]] && ((age > max_job_age)); then
    echo "Runner.Worker $oldest is ${age}s old (limit ${max_job_age}s); powering off"
    systemctl poweroff
  fi
  exit 0
fi

[[ -f "$idle_file" ]] || echo "$now" > "$idle_file"
idle_since=$(cat "$idle_file")
[[ "$idle_since" =~ ^[0-9]+$ ]] || { idle_since=$now; echo "$now" > "$idle_file"; }
idle=$((now - idle_since))

if ((uptime >= min_uptime && lease <= now && idle >= idle_limit)); then
  echo "idle ${idle}s, lease $lease expired, up ${uptime}s; powering off"
  systemctl poweroff
elif ((lease > now)); then
  echo "lease until $lease ($((lease - now))s left), idle ${idle}s"
else
  echo "lease expired, idle ${idle}s, up ${uptime}s"
fi
