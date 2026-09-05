#!/usr/bin/env python3
"""THROWAWAY: compile the identical caller against main and prototype; measure serially."""
import argparse
import csv
import hashlib
import json
import os
import pathlib
import random
import re
import shutil
import subprocess

root = pathlib.Path(__file__).resolve().parent
repo = root.parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--baseline', type=pathlib.Path, default=repo.parent / 'minip2p')
parser.add_argument('--repeats', type=int, default=7)
parser.add_argument('--allocation-repeats', type=int, default=3)
args = parser.parse_args()
baseline = args.baseline.resolve()
results = root / 'results/consumers'
results.mkdir(parents=True, exist_ok=True)
work = root / 'target/consumer-baseline'
(work / 'src').mkdir(parents=True, exist_ok=True)
source = root / 'src/bin/consumer_bench.rs'
shutil.copyfile(source, work / 'src/main.rs')
# Seed the baseline resolver with the prototype's pinned dependency versions.
shutil.copyfile(root / 'Cargo.lock', work / 'Cargo.lock')
manifest = f'''[package]
name = "consumer-bench-baseline"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
e2e = []
alloc-stats = ["dep:stats_alloc"]
[dependencies]
minip2p-rs = {{ path = {json.dumps(str(baseline / 'crates/minip2p'))}, default-features = false, features = ["std", "tcp"] }}
minip2p-tcp = {{ path = {json.dumps(str(baseline / 'transports/tcp'))}, features = ["std"] }}
stats_alloc = {{ version = "=0.1.10", optional = true }}
'''
(work / 'Cargo.toml').write_text(manifest)
fields = 'mode,size,pause_ms,rate,alloc_stats,elapsed_ms,mib_s,fast_done_us,slow_done_us,peak_payload,peak_slow,probes,probe_p50_us,probe_p99_us,probe_max_us,max_probe_gap_us,polls,sleeps,skip_polls,rejected,allocations,allocated_bytes,live_heap_peak_delta'.split(',')
extra = ['rss_peak_bytes', 'cpu_user_s', 'cpu_system_s', 'os_peak_footprint_bytes']
cases = [('active-32MiB', 32*1048576, 0, 0), ('paced-8MiB', 8*1048576, 0, 4*1048576), ('paused-8MiB', 8*1048576, 750, 0), ('paused-32MiB', 32*1048576, 750, 0)]
def capture(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()
def git(*arguments, cwd=repo):
    return capture(['git', *arguments], cwd=cwd)
if git('diff', 'HEAD', '--name-only', cwd=baseline):
    raise SystemExit('Baseline has tracked edits. Select a clean baseline checkout.')
metadata = {
    'baseline_revision': git('rev-parse', 'HEAD', cwd=baseline),
    'prototype_parent_revision': git('rev-parse', 'HEAD'),
    'prototype_diff_sha256': hashlib.sha256(capture(['git', 'diff', 'HEAD'], cwd=repo).encode()).hexdigest(),
    'caller_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'rustc': capture(['rustc', '-Vv']),
    'os': capture(['sw_vers']), 'cpu': capture(['sysctl', '-n', 'machdep.cpu.brand_string']),
    'flags': {key: os.environ.get(key, '') for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS')},
    'consumer_batch_bytes': 65536,
    'timing_repeats': args.repeats, 'allocation_repeats': args.allocation_repeats,
    'cases': cases, 'idle_sleep_us': 100, 'send_retry_ms': 1,
}
def measure(binary, mode, case):
    _, size, pause, rate = case
    result = subprocess.run(['/usr/bin/time', '-l', str(binary), mode, str(size), str(pause), str(rate), '100'], text=True, capture_output=True, check=True)
    row = next(csv.reader([result.stdout.strip()]))
    assert len(row) == len(fields), result.stdout
    rss = re.search(r'(\d+)\s+maximum resident set size', result.stderr)
    cpu = re.search(r'([\d.]+) real\s+([\d.]+) user\s+([\d.]+) sys', result.stderr)
    footprint = re.search(r'(\d+)\s+peak memory footprint', result.stderr)
    assert rss and cpu and footprint, result.stderr
    return row + [rss[1], cpu[2], cpu[3], footprint[1]]
for instrumented in (False, True):
    subprocess.run(['cargo', 'build', '--release', '--manifest-path', str(root/'Cargo.toml'), '--features', 'e2e,alloc-stats' if instrumented else 'e2e', '--bin', 'consumer-bench'], check=True)
    command = ['cargo', 'build', '--release', '--manifest-path', str(work/'Cargo.toml')]
    if instrumented:
        command += ['--features', 'alloc-stats']
    subprocess.run(command, check=True)
    main_bin = work / 'target/release/consumer-bench-baseline'
    pull_bin = root / 'target/release/consumer-bench'
    if not instrumented:
        versions = {}
        for label, path, features in [('main', work/'Cargo.toml', []), ('prototype', root/'Cargo.toml', ['--features', 'e2e'])]:
            data = json.loads(capture(['cargo','metadata','--format-version','1','--locked','--manifest-path',str(path),*features]))
            versions[label] = {p['name']: p['version'] for p in data['packages'] if p['source']}
        for name in versions['main'].keys() & versions['prototype'].keys():
            assert versions['main'][name] == versions['prototype'][name], (name, versions)
        metadata['registry_versions'] = versions
        (results/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
        shutil.copyfile(work/'Cargo.lock', results/'baseline.Cargo.lock')
        # Check whether using the branch changes current-mode behavior before interpreting pull.
        with (results/'branch-control.csv').open('w') as f:
            writer=csv.writer(f);writer.writerow(['build','run',*fields,*extra])
            for repeat in range(1,4):
                for label,binary in [('main',main_bin),('prototype',pull_bin)]:
                    writer.writerow([label,repeat,*measure(binary,'current',cases[0])])
    # Discard mode warmups before measuring; preserve only measured runs.
    for mode in ('current','pull','ack','pause'):
        measure(pull_bin if mode=='pull' else main_bin, mode, ('warmup',1048576,0,0))
    count = args.allocation_repeats if instrumented else args.repeats
    output = results / ('allocations.csv' if instrumented else 'timing.csv')
    rng = random.Random(149)
    with output.open('w') as f:
        writer=csv.writer(f);writer.writerow(['case','run',*fields,*extra])
        for case in cases:
            for repeat in range(1,count+1):
                modes=['current','pull','ack','pause'];rng.shuffle(modes)
                for mode in modes:
                    row=measure(pull_bin if mode=='pull' else main_bin, mode, case)
                    writer.writerow([case[0],repeat,*row]);f.flush()
                print(output.name, case[0], f'{repeat}/{count} complete', flush=True)
print('Results:', results)
