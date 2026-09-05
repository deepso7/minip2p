#!/usr/bin/env python3
"""Summarize recorded runs without discarding outliers."""
import csv
import statistics
from pathlib import Path
root = Path(__file__).resolve().parent / 'results/consumers'
rows = list(csv.DictReader((root/'timing.csv').open()))
alloc = list(csv.DictReader((root/'allocations.csv').open()))
lines = ['# Consumer benchmark medians', '', 'All recorded runs are included. Timing has seven repetitions per cell; allocation measurements have three.', '']
for case in dict.fromkeys(r['case'] for r in rows):
    lines += ['## '+case, '', '| Mode | MiB/s median [min, max] | Finish ms | Fast stream ms | Payload MiB | RSS MiB | Probe p99 ms | Probe max ms | CPU user + system s |', '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for mode in ('current','pull','ack','pause'):
        rr = [r for r in rows if r['case']==case and r['mode']==mode]
        def med(key, divisor=1):
            return statistics.median(float(r[key])/divisor for r in rr)
        speeds=[float(r['mib_s']) for r in rr]
        cpu=statistics.median(float(r['cpu_user_s'])+float(r['cpu_system_s']) for r in rr)
        lines.append(f"| {mode} | {statistics.median(speeds):.2f} [{min(speeds):.2f}, {max(speeds):.2f}] | {med('elapsed_ms'):.2f} | {med('fast_done_us',1000):.2f} | {med('peak_payload',1048576):.3f} | {med('rss_peak_bytes',1048576):.2f} | {med('probe_p99_us',1000):.3f} | {med('probe_max_us',1000):.3f} | {cpu:.2f} |")
    lines += ['', '| Mode | Allocation calls | Cumulative allocated MiB | Sampled incremental live heap MiB | Rejected sends |', '| --- | ---: | ---: | ---: | ---: |']
    for mode in ('current','pull','ack','pause'):
        rr=[r for r in alloc if r['case']==case and r['mode']==mode]
        def med(key,divisor=1):return statistics.median(float(r[key])/divisor for r in rr)
        lines.append(f"| {mode} | {med('allocations'):,.0f} | {med('allocated_bytes',1048576):.2f} | {med('live_heap_peak_delta',1048576):.3f} | {med('rejected'):,.0f} |")
    lines += ['']
(root/'summary.md').write_text('\n'.join(lines))
