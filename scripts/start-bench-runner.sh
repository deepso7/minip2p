#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?AWS_REGION is required}"
: "${AWS_BENCH_INSTANCE_ID:?AWS_BENCH_INSTANCE_ID is the bench instance ID}"

instance=$AWS_BENCH_INSTANCE_ID

ec2() {
  aws --region "$AWS_REGION" ec2 "$@"
}

ec2 create-tags --resources "$instance" \
  --tags "Key=bench-lease-until,Value=$(($(date +%s) + 1200))"

deadline=$((SECONDS + 600))
backoff=10
while ((SECONDS < deadline)); do
  state=$(ec2 describe-instances --instance-ids "$instance" \
    --query 'Reservations[0].Instances[0].State.Name' --output text)
  case $state in
    running)
      echo "$instance is running"
      exit 0
      ;;
    stopped)
      if ! error=$(ec2 start-instances --instance-ids "$instance" 2>&1 >/dev/null); then
        case $error in
          *InsufficientInstanceCapacity* | *IncorrectInstanceState*)
            echo "start-instances failed, retrying in ${backoff}s: $error"
            sleep "$backoff"
            backoff=$((backoff < 60 ? backoff * 2 : 60))
            continue
            ;;
          *)
            echo "$error" >&2
            exit 1
            ;;
        esac
      fi
      echo "Starting $instance"
      ;;
    stopping | pending | shutting-down)
      echo "$instance is $state"
      ;;
    *)
      echo "bench instance $instance is $state and cannot be started" >&2
      exit 1
      ;;
  esac
  sleep 10
done

echo "bench instance $instance was not running after 10 minutes" >&2
exit 1
