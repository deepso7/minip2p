#!/bin/sh
set -eu

ip route replace "${WAN_SUBNET}" via "${WAN_ROUTER_IP}" dev lan0
exec minip2p-hole-punch-interop "$@"
