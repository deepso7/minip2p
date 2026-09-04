#!/usr/bin/env python3
"""THROWAWAY real TCP comparison. Run from any directory; results replace prior CSVs."""
import csv
import pathlib
import random
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent
fields = 'mode,pause_ms,alloc_stats,elapsed_ms,mib_s,fast_done_us,peak_held_bytes,paused_held_bytes,peak_wire_bytes,probe_samples,probe_p50_us,probe_p99_us,turn_p99_us,allocations,reallocations,allocated_bytes,blocked_writes'.split(',')
(root / 'results').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='minip2p-tcp-') as tmp:
    fixture = pathlib.Path(tmp) / 'file.bin'
    fixture.write_bytes(random.Random(149).randbytes(8 * 1024 * 1024))
    for instrumented in (False, True):
        features = 'real-tcp,alloc-stats' if instrumented else 'real-tcp'
        subprocess.run(['cargo', 'build', '--release', '--manifest-path', str(root / 'Cargo.toml'), '--features', features, '--bin', 'real-tcp'], check=True)
        binary = root / 'target/release/real-tcp'
        name = 'allocations.csv' if instrumented else 'timing.csv'
        with (root / 'results' / name).open('w') as output:
            writer = csv.writer(output)
            writer.writerow(['run', *fields])
            # Discard warmups. Each measured run uses fresh sessions and sockets.
            for mode in ('owned', 'pull'):
                subprocess.run([str(binary), mode, str(fixture), '0'], check=True, stdout=subprocess.DEVNULL)
            for pause in (0, 200):
                for repeat in range(1, 6):
                    modes = ('owned', 'pull') if repeat % 2 else ('pull', 'owned')
                    for mode in modes:
                        line = subprocess.check_output([str(binary), mode, str(fixture), str(pause)], text=True).strip()
                        writer.writerow([repeat, *line.split(',')])
                        output.flush()
                        print(name, repeat, line, flush=True)
