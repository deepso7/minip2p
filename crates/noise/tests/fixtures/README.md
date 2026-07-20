# Noise interoperability fixtures

Normal tests consume only the checked-in fixture bytes in this directory.
Neither external producer is part of the minip2p workspace or its CI dependency
graph.

- `noise-c-basic-xx.txt` is the `Noise_XX_25519_ChaChaPoly_SHA256` entry from
  noise-c commit `5d0a74760320e5486ced302e36ccad91606aac43`. Run
  `./regenerate-noise-c.sh` to print the pinned upstream JSON.
- `libp2p-noise-0.46.1.txt` is an initiator transcript from exactly
  `libp2p-noise` 0.46.1. The producer's identity, Noise static, Noise ephemeral,
  and responder keys are all fixed. To reproduce the transcript, run:

  ```sh
  ./regenerate-libp2p.sh
  ```

The script verifies the crates.io checksum, applies deterministic test-only key
substitutions to the downloaded producer source, and keeps that source and its
build output in a temporary directory. The producer also compares minip2p's
message 2 against a fixed-key `snow` 0.9.6 responder before emitting anything.
The generator's committed lockfile is resolved for this patched producer
workflow, which is its supported execution path.
