#!/usr/bin/env python3
"""THROWAWAY Endpoint file-transfer comparison. Replaces only e2e CSV results."""
import csv
import pathlib
import random
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent
fields = 'mode,pause_ms,alloc_stats,elapsed_ms,mib_s,fast_done_us,peak_held_bytes,probe_samples,probe_p99_us,allocations,allocated_bytes'.split(',')
with tempfile.TemporaryDirectory(prefix='minip2p-endpoint-e2e-') as tmp:
    fixture = pathlib.Path(tmp) / 'source.bin'
    fixture.write_bytes(random.Random(149).randbytes(8 * 1024 * 1024))
    for instrumented in (False, True):
        features = 'e2e,alloc-stats' if instrumented else 'e2e'
        subprocess.run(['cargo', 'build', '--release', '--manifest-path', str(root / 'Cargo.toml'), '--features', features, '--bin', 'endpoint-e2e'], check=True)
        binary = root / 'target/release/endpoint-e2e'
        name = 'e2e-allocations.csv' if instrumented else 'e2e-timing.csv'
        with (root / 'results' / name).open('w') as output:
            writer = csv.writer(output)
            writer.writerow(['run', *fields])
            for mode in ('pull', 'chunk'):
                subprocess.run([str(binary), mode, str(fixture), tmp, '0'], check=True, stdout=subprocess.DEVNULL)
            for pause in (0, 200):
                for repeat in range(1, 6):
                    modes = ('pull', 'chunk') if repeat % 2 else ('chunk', 'pull')
                    for mode in modes:
                        line = subprocess.check_output([str(binary), mode, str(fixture), tmp, str(pause)], text=True).strip()
                        writer.writerow([repeat, *line.split(',')])
                        output.flush()
                        print(name, repeat, line, flush=True)
