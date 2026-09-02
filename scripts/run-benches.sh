#!/usr/bin/env bash
set -eu

git_sha=${BENCH_GIT_SHA:-$(git rev-parse HEAD)}

case "${1:-}" in
wall)
  python3 scripts/bench_results.py start --output target/bench-results/criterion-start
  cargo bench -p minip2p-core --bench multiaddr
  cargo bench -p minip2p-yamux --bench data_path
  cargo bench -p minip2p-discovery --bench peer_book
  cargo bench -p minip2p-pubsub --bench fanout
  cargo bench -p minip2p-relay-server --bench relay_server_event
  cargo bench -p minip2p-quic --bench idle_poll
  cargo bench -p minip2p-tcp --bench readiness_poll
  cargo bench -p minip2p-rs --features tcp --bench endpoint_e2e
  python3 scripts/bench_results.py criterion --since target/bench-results/criterion-start --output target/bench-results/rust-wall.json --git-sha "$git_sha"
  ;;
ir)
  python3 scripts/bench_results.py start --output target/bench-results/gungraun-start
  GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-core --bench multiaddr_ir
  GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-yamux --bench data_path_ir
  GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-discovery --bench peer_book_ir
  GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-pubsub --bench fanout_ir
  GUNGRAUN_SAVE_SUMMARY=json cargo bench -p minip2p-relay-server --bench relay_server_event_ir
  python3 scripts/bench_results.py gungraun --since target/bench-results/gungraun-start --output target/bench-results/rust-micro.json --git-sha "$git_sha"
  ;;
*)
  echo "usage: $0 wall|ir" >&2
  exit 2
  ;;
esac
