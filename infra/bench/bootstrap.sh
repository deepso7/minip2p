#!/usr/bin/env bash
# Provision the on-demand EC2 bench runner and the CI role's permissions.
# Idempotent: resources are found by tag, so reruns converge instead of
# duplicating. Needs administrator credentials and `gh` logged in as a repo
# admin (for the runner registration token).
#
#   infra/bench/bootstrap.sh                     create what is missing, update the CI role
#   infra/bench/bootstrap.sh --replace           terminate the instance and create a fresh one
#   infra/bench/bootstrap.sh --ssh-from <cidr>   add a port-22 ingress rule (nothing else)
#   infra/bench/bootstrap.sh --no-ssh            remove every port-22 ingress rule (nothing else)
#   infra/bench/bootstrap.sh --render-user-data <file>
#                                                write the user data with a dummy token; no AWS calls
#
# Env: AWS_BENCH_REGION (default us-east-1), BENCH_INSTANCE_TYPE (default
# c7a.xlarge), BENCH_SSH_KEY (private key path, default ~/.ssh/minip2p-bench.pem).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=deepso7/minip2p
name=minip2p-bench
sg_name=minip2p-bench-runner
role=minip2p-github-bench
instance_type=${BENCH_INSTANCE_TYPE:-c7a.xlarge}
key_file=${BENCH_SSH_KEY:-$HOME/.ssh/minip2p-bench.pem}
lease_tag=bench-lease-until

replace=false
mode=provision
ssh_cidr=
render_out=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --replace) replace=true ;;
    --ssh-from) mode=ssh-from; ssh_cidr=${2:?--ssh-from needs a CIDR}; shift ;;
    --no-ssh) mode=no-ssh ;;
    --render-user-data) mode=render; render_out=${2:?--render-user-data needs a file}; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# Print cloud-init.yaml with the scripts embedded and the given registration
# token filled in. The output holds a live token: never print or log it.
render_user_data() {
  local token=$1 b64
  local -A files=(
    [JOB_STARTED_B64]=runner-hooks/job-started.sh
    [WATCHDOG_B64]=watchdog.sh
    [WATCHDOG_SERVICE_B64]=minip2p-bench-watchdog.service
    [WATCHDOG_TIMER_B64]=minip2p-bench-watchdog.timer
  )
  local doc
  doc=$(<"$here/cloud-init.yaml")
  for key in "${!files[@]}"; do
    b64=$(base64 -w0 "$here/${files[$key]}")
    doc=${doc//"@@$key@@"/$b64}
  done
  doc=${doc//"@@RUNNER_TOKEN@@"/$token}
  printf '%s\n' "$doc"
}

if [[ "$mode" == render ]]; then
  (umask 077; render_user_data DUMMY-REGISTRATION-TOKEN > "$render_out")
  echo "wrote $render_out: $(wc -c < "$render_out") bytes, $(gzip -9c "$render_out" | wc -c) gzipped (limit 16384)"
  exit 0
fi

region=${AWS_BENCH_REGION:-us-east-1}
export AWS_REGION="$region" AWS_DEFAULT_REGION="$region"
account=$(aws sts get-caller-identity --query Account --output text)
tags="{Key=project,Value=minip2p},{Key=Name,Value=$name}"

# First ID of a tagged resource, or empty. $1 is the describe subcommand, $2
# the JMESPath to the IDs; extra arguments are added filters.
find_tagged() {
  local cmd=$1 query=$2
  shift 2
  aws ec2 "$cmd" --filters Name=tag:project,Values=minip2p "Name=tag:Name,Values=$name" "$@" \
    --query "$query" --output text | awk 'NF && $1 != "None" { print $1; exit }'
}

find_instance() {
  find_tagged describe-instances 'Reservations[].Instances[].InstanceId' \
    Name=instance-state-name,Values=pending,running,stopping,stopped
}

find_sg() {
  aws ec2 describe-security-groups \
    --filters Name=tag:project,Values=minip2p "Name=group-name,Values=$sg_name" \
    --query 'SecurityGroups[0].GroupId' --output text | grep -v '^None$' || true
}

# --- SSH access only ---------------------------------------------------------
if [[ "$mode" == ssh-from || "$mode" == no-ssh ]]; then
  sg=$(find_sg)
  [[ -n "$sg" ]] || { echo "security group $sg_name not found; run bootstrap first" >&2; exit 1; }
  if [[ "$mode" == ssh-from ]]; then
    aws ec2 authorize-security-group-ingress --group-id "$sg" \
      --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$ssh_cidr,Description=bench-admin}]" \
      >/dev/null
    echo "allowed SSH from $ssh_cidr on $sg"
  else
    mapfile -t rules < <(aws ec2 describe-security-group-rules \
      --filters "Name=group-id,Values=$sg" \
      --query 'SecurityGroupRules[?!IsEgress && FromPort<=`22` && ToPort>=`22`].SecurityGroupRuleId' \
      --output text | tr '\t' '\n' | grep . || true)
    if [[ ${#rules[@]} -gt 0 ]]; then
      aws ec2 revoke-security-group-ingress --group-id "$sg" --security-group-rule-ids "${rules[@]}" >/dev/null
    fi
    echo "removed ${#rules[@]} SSH rule(s) from $sg"
  fi
  exit 0
fi

echo "Bootstrapping the minip2p bench runner in $account/$region"

# --- Network: one /24 VPC, one public subnet, egress via an IGW only ---------
vpc=$(find_tagged describe-vpcs 'Vpcs[].VpcId')
if [[ -z "$vpc" ]]; then
  vpc=$(aws ec2 create-vpc --cidr-block 10.77.0.0/24 \
    --tag-specifications "ResourceType=vpc,Tags=[$tags]" --query Vpc.VpcId --output text)
  aws ec2 wait vpc-available --vpc-ids "$vpc"
  echo "created VPC $vpc"
fi

subnet=$(find_tagged describe-subnets 'Subnets[].SubnetId' "Name=vpc-id,Values=$vpc")
if [[ -z "$subnet" ]]; then
  # Not every AZ offers every instance type; pick one that does.
  az=$(aws ec2 describe-instance-type-offerings --location-type availability-zone \
    --filters "Name=instance-type,Values=$instance_type" \
    --query 'InstanceTypeOfferings[].Location' --output text | tr '\t' '\n' | sort | head -n1)
  [[ -n "$az" ]] || { echo "$instance_type is not offered in $region" >&2; exit 1; }
  subnet=$(aws ec2 create-subnet --vpc-id "$vpc" --cidr-block 10.77.0.0/24 --availability-zone "$az" \
    --tag-specifications "ResourceType=subnet,Tags=[$tags]" --query Subnet.SubnetId --output text)
  echo "created subnet $subnet in $az"
fi

igw=$(find_tagged describe-internet-gateways 'InternetGateways[].InternetGatewayId')
if [[ -z "$igw" ]]; then
  igw=$(aws ec2 create-internet-gateway \
    --tag-specifications "ResourceType=internet-gateway,Tags=[$tags]" \
    --query InternetGateway.InternetGatewayId --output text)
  echo "created internet gateway $igw"
fi
attached=$(aws ec2 describe-internet-gateways --internet-gateway-ids "$igw" \
  --query 'InternetGateways[0].Attachments[0].VpcId' --output text)
if [[ "$attached" != "$vpc" ]]; then
  aws ec2 attach-internet-gateway --internet-gateway-id "$igw" --vpc-id "$vpc"
fi

rtb=$(find_tagged describe-route-tables 'RouteTables[].RouteTableId' "Name=vpc-id,Values=$vpc")
if [[ -z "$rtb" ]]; then
  rtb=$(aws ec2 create-route-table --vpc-id "$vpc" \
    --tag-specifications "ResourceType=route-table,Tags=[$tags]" \
    --query RouteTable.RouteTableId --output text)
  echo "created route table $rtb"
fi
aws ec2 create-route --route-table-id "$rtb" --destination-cidr-block 0.0.0.0/0 --gateway-id "$igw" >/dev/null 2>&1 \
  || aws ec2 replace-route --route-table-id "$rtb" --destination-cidr-block 0.0.0.0/0 --gateway-id "$igw"
associated=$(aws ec2 describe-route-tables --route-table-ids "$rtb" \
  --query "RouteTables[0].Associations[?SubnetId=='$subnet'].SubnetId" --output text)
if [[ -z "$associated" || "$associated" == None ]]; then
  aws ec2 associate-route-table --route-table-id "$rtb" --subnet-id "$subnet" >/dev/null
fi

# No inbound rules; the default allow-all egress stays.
sg=$(find_sg)
if [[ -z "$sg" ]]; then
  sg=$(aws ec2 create-security-group --group-name "$sg_name" --vpc-id "$vpc" \
    --description "minip2p bench runner: no inbound" \
    --tag-specifications "ResourceType=security-group,Tags=[{Key=project,Value=minip2p},{Key=Name,Value=$sg_name}]" \
    --query GroupId --output text)
  echo "created security group $sg"
fi

# --- Key pair: the private key stays on this machine ---------------------------
if ! aws ec2 describe-key-pairs --key-names "$name" >/dev/null 2>&1; then
  mkdir -p "$(dirname "$key_file")"
  (umask 077; aws ec2 create-key-pair --key-name "$name" --key-type ed25519 \
    --tag-specifications "ResourceType=key-pair,Tags=[$tags]" \
    --query KeyMaterial --output text > "$key_file")
  chmod 600 "$key_file"
  echo "created key pair $name; private key in $key_file"
elif [[ ! -f "$key_file" ]]; then
  echo "note: key pair $name exists but $key_file is missing; SSH needs the original key" >&2
fi

# --- Instance -----------------------------------------------------------------
instance=$(find_instance)
if [[ -n "$instance" && "$replace" == true ]]; then
  aws ec2 terminate-instances --instance-ids "$instance" >/dev/null
  echo "terminating $instance"
  aws ec2 wait instance-terminated --instance-ids "$instance"
  instance=
fi

if [[ -z "$instance" ]]; then
  ami=$(aws ssm get-parameter \
    --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
    --query Parameter.Value --output text)
  root_device=$(aws ec2 describe-images --image-ids "$ami" --query 'Images[0].RootDeviceName' --output text)

  # The rendered user data holds the registration token: keep it in a private
  # temp file, gzip it (cloud-init accepts gzip) to stay under 16 KB, and
  # remove it on exit.
  workdir=$(mktemp -d)
  trap 'rm -rf "$workdir"' EXIT
  token=$(gh api -X POST "repos/$repo/actions/runners/registration-token" --jq .token)
  render_user_data "$token" | gzip -9 > "$workdir/user-data.gz"
  unset token
  size=$(wc -c < "$workdir/user-data.gz")
  ((size <= 16384)) || { echo "user data is $size bytes gzipped; limit 16384" >&2; exit 1; }

  instance=$(aws ec2 run-instances \
    --image-id "$ami" \
    --instance-type "$instance_type" \
    --key-name "$name" \
    --network-interfaces "DeviceIndex=0,SubnetId=$subnet,Groups=$sg,AssociatePublicIpAddress=true" \
    --block-device-mappings "DeviceName=$root_device,Ebs={VolumeSize=80,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}" \
    --metadata-options HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=1,InstanceMetadataTags=enabled \
    --instance-initiated-shutdown-behavior stop \
    --tag-specifications "ResourceType=instance,Tags=[$tags]" "ResourceType=volume,Tags=[$tags]" \
    --user-data "fileb://$workdir/user-data.gz" \
    --query 'Instances[0].InstanceId' --output text)
  echo "launched $instance ($instance_type, $ami); first-boot setup takes a few minutes"
fi

# --- CI role: trust both environments, start and lease only this instance ------
if ! aws iam get-role --role-name "$role" >/dev/null 2>&1; then
  echo "role $role not found; create it per README.md, then rerun" >&2
  exit 1
fi
aws iam update-assume-role-policy --role-name "$role" --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::'"$account"':oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": [
        "repo:'"$repo"':environment:aws-bench",
        "repo:'"$repo"':environment:aws-bench-keepalive"
      ]
    }}
  }]
}'

# Converge to exactly one inline policy and no attached ones. JSON output
# distinguishes an empty list from a policy named `None`.
policy_name=minip2p-bench-start
mapfile -t inline < <(aws iam list-role-policies --role-name "$role" --query PolicyNames --output json | jq -r '.[]')
for p in "${inline[@]}"; do
  [[ "$p" == "$policy_name" ]] || aws iam delete-role-policy --role-name "$role" --policy-name "$p"
done
mapfile -t attached_arns < <(aws iam list-attached-role-policies --role-name "$role" \
  --query 'AttachedPolicies[].PolicyArn' --output json | jq -r '.[]')
for arn in "${attached_arns[@]}"; do
  aws iam detach-role-policy --role-name "$role" --policy-arn "$arn"
done

instance_arn="arn:aws:ec2:$region:$account:instance/$instance"
aws iam put-role-policy --role-name "$role" --policy-name "$policy_name" --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "Start", "Effect": "Allow", "Action": "ec2:StartInstances", "Resource": "'"$instance_arn"'"},
    {
      "Sid": "Lease",
      "Effect": "Allow",
      "Action": "ec2:CreateTags",
      "Resource": "'"$instance_arn"'",
      "Condition": {
        "ForAllValues:StringEquals": {"aws:TagKeys": ["'"$lease_tag"'"]},
        "Null": {"aws:TagKeys": "false"}
      }
    },
    {"Sid": "Describe", "Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
  ]
}'
echo "updated $role: trust aws-bench + aws-bench-keepalive, policy $policy_name"

echo
echo "Set AWS_BENCH_INSTANCE_ID=$instance on the aws-bench and aws-bench-keepalive environments."
