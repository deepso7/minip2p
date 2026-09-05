# Consumer benchmark medians

All recorded runs are included. Timing has seven repetitions per cell; allocation measurements have three.

## active-32MiB

| Mode | MiB/s median [min, max] | Finish ms | Fast stream ms | Payload MiB | RSS MiB | Probe p99 ms | Probe max ms | CPU user + system s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current | 268.50 [257.73, 269.21] | 238.36 | 238.34 | 0.188 | 3.81 | 1.423 | 1.436 | 0.23 |
| pull | 259.21 [252.70, 260.47] | 246.90 | 246.84 | 0.188 | 4.55 | 1.496 | 1.752 | 0.24 |
| ack | 258.06 [253.70, 263.85] | 248.00 | 247.98 | 0.188 | 3.88 | 1.502 | 1.542 | 0.24 |
| pause | 267.83 [250.83, 268.66] | 238.96 | 238.94 | 0.188 | 3.84 | 1.425 | 1.449 | 0.23 |

| Mode | Allocation calls | Cumulative allocated MiB | Sampled incremental live heap MiB | Rejected sends |
| --- | ---: | ---: | ---: | ---: |
| current | 34,144 | 528.57 | 0.625 | 0 |
| pull | 32,017 | 567.31 | 1.188 | 0 |
| ack | 45,090 | 548.14 | 0.750 | 0 |
| pause | 34,224 | 545.34 | 0.750 | 0 |

## paced-8MiB

| Mode | MiB/s median [min, max] | Finish ms | Fast stream ms | Payload MiB | RSS MiB | Probe p99 ms | Probe max ms | CPU user + system s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current | 8.00 [8.00, 8.00] | 2000.19 | 61.34 | 7.875 | 11.62 | 1.013 | 1.515 | 0.19 |
| pull | 8.00 [8.00, 8.00] | 2000.14 | 34.76 | 0.375 | 5.06 | 0.689 | 2.562 | 0.20 |
| ack | 8.00 [8.00, 8.00] | 2000.09 | 33.62 | 0.375 | 4.25 | 0.518 | 0.948 | 0.20 |
| pause | 8.00 [8.00, 8.00] | 2000.12 | 1922.32 | 0.312 | 5.27 | 47.062 | 61.540 | 0.16 |

| Mode | Allocation calls | Cumulative allocated MiB | Sampled incremental live heap MiB | Rejected sends |
| --- | ---: | ---: | ---: | ---: |
| current | 239,911 | 149.50 | 8.379 | 0 |
| pull | 248,001 | 260.05 | 1.125 | 1,703 |
| ack | 248,364 | 144.12 | 0.749 | 0 |
| pause | 120,036 | 368.46 | 1.313 | 3,504 |

## paused-8MiB

| Mode | MiB/s median [min, max] | Finish ms | Fast stream ms | Payload MiB | RSS MiB | Probe p99 ms | Probe max ms | CPU user + system s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current | 21.14 [21.13, 21.15] | 756.74 | 60.42 | 8.062 | 11.66 | 1.010 | 1.435 | 0.10 |
| pull | 20.44 [20.42, 20.46] | 782.62 | 34.37 | 0.375 | 4.55 | 0.678 | 1.034 | 0.10 |
| ack | 20.46 [20.44, 20.47] | 782.03 | 32.72 | 0.375 | 4.22 | 0.583 | 0.973 | 0.11 |
| pause | 19.74 [19.54, 19.76] | 810.45 | 810.33 | 0.312 | 5.38 | 2.043 | 749.909 | 0.09 |

| Mode | Allocation calls | Cumulative allocated MiB | Sampled incremental live heap MiB | Rejected sends |
| --- | ---: | ---: | ---: | ---: |
| current | 93,251 | 139.78 | 8.566 | 0 |
| pull | 98,667 | 182.20 | 0.937 | 673 |
| ack | 100,621 | 137.52 | 0.750 | 0 |
| pause | 49,570 | 237.55 | 1.312 | 1,458 |

## paused-32MiB

| Mode | MiB/s median [min, max] | Finish ms | Fast stream ms | Payload MiB | RSS MiB | Probe p99 ms | Probe max ms | CPU user + system s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| current | 82.66 [81.89, 82.91] | 774.29 | 241.17 | 32.062 | 35.83 | 1.456 | 1.508 | 0.28 |
| pull | 72.84 [72.64, 72.93] | 878.65 | 134.61 | 0.375 | 4.77 | 0.623 | 1.053 | 0.29 |
| ack | 72.56 [72.41, 72.77] | 881.98 | 132.35 | 0.375 | 4.30 | 0.603 | 0.949 | 0.30 |
| pause | 64.11 [63.83, 64.50] | 998.25 | 998.16 | 0.312 | 4.89 | 1.849 | 749.764 | 0.27 |

| Mode | Allocation calls | Cumulative allocated MiB | Sampled incremental live heap MiB | Rejected sends |
| --- | ---: | ---: | ---: | ---: |
| current | 102,931 | 547.11 | 32.578 | 0 |
| pull | 116,517 | 597.81 | 0.937 | 675 |
| ack | 131,578 | 526.49 | 0.750 | 0 |
| pause | 75,282 | 671.48 | 1.187 | 1,460 |
