#!/usr/bin/env python3
"""Check that the Gungraun bench ids in the `ir` targets of bench/targets match
`GUNGRAUN_NAMES` in scripts/bench_results.py, so a new or renamed IR bench
fails CI instead of the results merge on the bench instance."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from bench_results import GUNGRAUN_NAMES  # noqa: E402

# A `#[library_benchmark]` function reports one id per `#[bench::<id>(...)]`
# attribute, or its own name when it has none (`summary.json`'s `id` or
# `function_name`, as `bench_results.py gungraun` reads them).
ATTRIBUTE = re.compile(r"#\[\s*(bench|benches)::(\w+)")
FUNCTION = re.compile(r"\bfn\s+(\w+)")


def bench_ids(source: str, path: Path) -> list[str]:
    ids = []
    for block in source.split("#[library_benchmark]")[1:]:
        function = FUNCTION.search(block)
        attributes = ATTRIBUTE.findall(block[: function.start()])
        if any(kind == "benches" for kind, _ in attributes):
            sys.exit(f"{path}: `#[benches::...]` ids are not supported by this check; extend it")
        ids.extend([name for _, name in attributes] or [function.group(1)])
    return ids


def main() -> int:
    targets = {
        (fields[1], fields[3])
        for line in (ROOT / "bench/targets").read_text().splitlines()
        if (fields := line.split()) and fields[0] == "ir"
    }
    metadata = json.loads(
        subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"], cwd=ROOT)
    )
    sources = {
        (package["name"], target["name"]): Path(target["src_path"])
        for package in metadata["packages"]
        for target in package["targets"]
        if "bench" in target["kind"]
    }
    errors = []
    # Every Gungraun bench target must be run by the `ir` pass.
    for key, path in sorted(sources.items()):
        if "gungraun::main!" in path.read_text() and key not in targets:
            errors.append(f"{key[0]} bench {key[1]} uses Gungraun but is not an `ir` line in bench/targets")
    ids: list[str] = []
    for key in sorted(targets):
        if key not in sources:
            errors.append(f"bench/targets: {key[0]} has no bench target {key[1]}")
            continue
        ids.extend(bench_ids(sources[key].read_text(), sources[key]))
    duplicates = sorted({name for name in ids if ids.count(name) > 1})
    missing = sorted(set(ids) - GUNGRAUN_NAMES.keys())
    stale = sorted(GUNGRAUN_NAMES.keys() - set(ids))
    if duplicates:
        errors.append(f"duplicate Gungraun ids: {duplicates}")
    if missing:
        errors.append(f"Gungraun ids missing from GUNGRAUN_NAMES in scripts/bench_results.py: {missing}")
    if stale:
        errors.append(f"GUNGRAUN_NAMES entries no IR bench defines: {stale}")
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if not errors:
        print(f"{len(ids)} Gungraun ids match GUNGRAUN_NAMES")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
