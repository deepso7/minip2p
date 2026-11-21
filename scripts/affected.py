#!/usr/bin/env python3
"""Compute diff-reachable CI targets for minip2p pull requests.

Uses `cargo metadata --no-deps` and Cargo feature-activation rules to determine
which workspace crates, feature-matrix rows, benchmarks, fuzz targets, docs,
and TypeScript bindings a given set of changed files can reach.

Unknown or global files (root Cargo.toml, Cargo.lock, CI workflows/actions,
shared verification scripts) fail open and trigger the full suite.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

LIB_CHECK_ROWS = (
    "relay-server",
    "relay-relay-server",
    "relay-relay-server-tcp",
    "bare-tcp-relay-server",
)

FULL_TRIGGER_FILES = frozenset(
    {
        "Cargo.toml",
        "Cargo.lock",
        ".config/nextest.toml",
        ".github/workflows/ci.yml",
        "scripts/affected.py",
        "scripts/run-feature-matrix.sh",
        "scripts/check-targets.sh",
        "scripts/publish-order.py",
    }
)

FULL_TRIGGER_PREFIXES = (
    ".cargo/",
    ".github/actions/",
)

NOOP_META_FILES = frozenset(
    {
        "AGENTS.md",
        "CHANGELOG.md",
        "GLOSSARY.md",
        "LICENSE",
        "README.md",
        "justfile",
        "skills-lock.json",
        ".github/dependabot.yml",
        "scripts/README.md",
        "scripts/check-comments.py",
        "scripts/clean.sh",
        "scripts/comment-baseline.json",
        "scripts/npm-trusted-publisher-web.sh",
        "scripts/prune-caches.sh",
        "scripts/release.sh",
        "scripts/start-bench-runner.sh",
        "scripts/test_affected.py",
    }
)

NOOP_META_PREFIXES = (
    ".agents/",
    ".claude/",
    "docs/adr/",
    "docs/agents/",
    "docs/plans/",
    "docs/research/",
    "tests/interop/",
)

WORKFLOW_TEST_PATHS = (
    ".github/workflows/bindings-native.yml",
    ".github/workflows/publish.yml",
    ".github/workflows/relay-container.yml",
    ".github/workflows/bench.yml",
    "bindings/ts/tests/workflows/",
    "bindings/ts/scripts/node-platform-manifest.mjs",
    "bindings/ts/node-platforms/",
    "scripts/build-node-musl.sh",
    "scripts/publish-crates.sh",
    "scripts/publish-npm-packages.sh",
    "scripts/verify-release-versions.sh",
)

RELAY_CONTAINER_FILES = frozenset(
    {
        "scripts/build-relay-release.sh",
        "scripts/check-relay-image.sh",
        "scripts/package-relay-server.sh",
        "scripts/relay-builder.Dockerfile",
        "scripts/test-relay-container.sh",
    }
)

RELAY_INSTALLER_FILES = frozenset(
    {
        "docs/public/install/relay.sh",
        "scripts/test-relay-installer.sh",
    }
)

BENCH_FILES = frozenset(
    {
        "scripts/bench_results.py",
        "scripts/build-benches.sh",
        "scripts/check-bench-ids.py",
        "scripts/rtt-sweep.sh",
        "scripts/run-bench-container.sh",
        "scripts/run-benches.sh",
        "scripts/run-container-benches.sh",
    }
)

TS_CONFIG_FILES = frozenset(
    {
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        "turbo.json",
    }
)

LINT_CONFIG_FILES = frozenset(
    {
        "oxfmt.config.ts",
        "oxlint.config.ts",
    }
)

ULTRACITE_SUFFIXES = frozenset(
    {
        ".cjs",
        ".css",
        ".html",
        ".js",
        ".json",
        ".jsonc",
        ".jsx",
        ".md",
        ".mdx",
        ".mjs",
        ".mts",
        ".ts",
        ".tsx",
        ".yaml",
        ".yml",
    }
)

ULTRACITE_IGNORED_PREFIXES = (
    ".agents/",
    ".claude/",
    "code-ref/",
    "bindings/ts/react-native/src/generated/",
    "bindings/ts/react-native/lib/",
    "bindings/ts/web/wasm/",
    "examples/react-native/android/",
    "examples/react-native/ios/",
)

ULTRACITE_IGNORED_FILES = frozenset(
    {
        "bindings/ts/react-native/src/NativeMinip2p.ts",
        "bindings/ts/react-native/src/native.tsx",
        "bindings/ts/node/src/addon.d.ts",
    }
)

NOSTD_ROOTS: tuple[tuple[str, bool, tuple[str, ...]], ...] = (
    ("minip2p-core", False, ()),
    ("minip2p-identity", False, ()),
    ("minip2p-transport", False, ()),
    ("minip2p-tls", False, ()),
    ("minip2p-secure-mux", False, ()),
    ("minip2p-smoltcp", False, ()),
    ("minip2p-tcp", False, ("smoltcp",)),
    ("minip2p-circuit", False, ()),
    ("minip2p-identify", False, ()),
    ("minip2p-multistream-select", False, ()),
    ("minip2p-ping", False, ()),
    ("minip2p-pubsub", False, ()),
    ("minip2p-discovery", False, ()),
    ("minip2p-mdns", False, ("smoltcp",)),
    ("minip2p-relay", False, ()),
    ("minip2p-relay-server", False, ()),
    ("minip2p-swarm", False, ()),
    ("minip2p-nat", False, ()),
    ("minip2p-webtransport", False, ()),
    ("minip2p-rs", False, ("smoltcp", "pubsub", "autonat", "relay", "discovery", "mdns", "relay-server")),
)

WASM_ROOTS: tuple[tuple[str, bool, tuple[str, ...]], ...] = (
    ("minip2p-ffi-core", False, ("serde",)),
    ("minip2p-rs", False, ("pubsub",)),
    ("minip2p-webtransport", False, ()),
    ("minip2p-web", True, ()),
)


def load_workspace_metadata(root: Path = ROOT) -> dict[str, Any]:
    """Return workspace package records indexed by crate name."""
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    data = json.loads(raw)
    packages: dict[str, Any] = {}
    for pkg in data["packages"]:
        manifest_dir = Path(pkg["manifest_path"]).parent.resolve().relative_to(root.resolve()).as_posix()
        packages[pkg["name"]] = {
            "name": pkg["name"],
            "dir": manifest_dir,
            "features": pkg["features"],
            "dependencies": pkg["dependencies"],
        }
    return packages


def parse_feature_matrix(root: Path = ROOT) -> list[dict[str, Any]]:
    """Parse matrix rows from scripts/run-feature-matrix.sh."""
    text = (root / "scripts" / "run-feature-matrix.sh").read_text(encoding="utf-8")
    match = re.search(r"matrix=\$\(cat <<'EOF'\n(.*?)\nEOF\n\)", text, re.DOTALL)
    if not match:
        raise RuntimeError("could not find matrix table in scripts/run-feature-matrix.sh")
    rows = []
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line:
            continue
        name, package, defaults, features_csv, tier = line.split("|")
        features = tuple(f for f in features_csv.split(",") if f)
        rows.append(
            {
                "name": name,
                "package": package,
                "default_features": defaults != "no-default",
                "features": features,
                "tier": tier,
            }
        )
    return rows


def parse_bench_targets(root: Path = ROOT) -> list[dict[str, Any]]:
    """Parse benchmark definitions from bench/targets."""
    rows = []
    for raw in (root / "bench" / "targets").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tier, package, features_csv, target = line.split()
        features = () if features_csv == "-" else tuple(f for f in features_csv.split(",") if f)
        rows.append(
            {
                "tier": tier,
                "package": package,
                "features": features,
                "target": target,
            }
        )
    return rows


def resolve_feature_closure(
    packages: dict[str, Any],
    root_pkg: str,
    use_default: bool = True,
    extra_features: tuple[str, ...] = (),
    include_dev: bool = False,
) -> set[str]:
    """Compute workspace crates activated by root_pkg under the given features."""
    if root_pkg not in packages:
        return set()

    active_pkgs: set[str] = set()
    active_feats: set[tuple[str, str]] = set()
    active_opt_deps: set[tuple[str, str]] = set()
    weak_dep_feats: dict[tuple[str, str], set[str]] = {}
    queue: list[tuple[str, Any]] = []

    def dep_key(dep: dict[str, Any]) -> str:
        return dep.get("rename") or dep["name"]

    def matching_deps(pkg_name: str, key: str, allow_dev: bool) -> list[dict[str, Any]]:
        result = []
        for dep in packages[pkg_name]["dependencies"]:
            if dep["name"] not in packages:
                continue
            kind = dep.get("kind")
            if kind == "dev" and not allow_dev:
                continue
            if dep_key(dep) == key:
                result.append(dep)
        return result

    def activate_dep(dep: dict[str, Any]) -> None:
        target = dep["name"]
        activate_pkg(target)
        if dep.get("uses_default_features", True) and "default" in packages[target]["features"]:
            activate_feat(target, "default")
        for feat in dep.get("features", ()):
            activate_feat(target, feat)

    def activate_opt_dep(pkg_name: str, key: str) -> None:
        pair = (pkg_name, key)
        if pair in active_opt_deps:
            return
        active_opt_deps.add(pair)
        allow_dev = include_dev and pkg_name == root_pkg
        for dep in matching_deps(pkg_name, key, allow_dev):
            activate_dep(dep)
            for subfeat in weak_dep_feats.get(pair, ()):
                activate_feat(dep["name"], subfeat)

    def activate_pkg(pkg_name: str) -> None:
        if pkg_name in active_pkgs:
            return
        active_pkgs.add(pkg_name)
        queue.append(("pkg", pkg_name))

    def activate_feat(pkg_name: str, feat: str) -> None:
        pair = (pkg_name, feat)
        if pair in active_feats:
            return
        active_feats.add(pair)
        queue.append(("feat", pair))

    activate_pkg(root_pkg)
    if use_default and "default" in packages[root_pkg]["features"]:
        activate_feat(root_pkg, "default")
    for feat in extra_features:
        activate_feat(root_pkg, feat)

    while queue:
        kind, payload = queue.pop()
        if kind == "pkg":
            pkg_name = payload
            allow_dev = include_dev and pkg_name == root_pkg
            for dep in packages[pkg_name]["dependencies"]:
                if dep["name"] not in packages:
                    continue
                if dep.get("kind") == "dev" and not allow_dev:
                    continue
                if not dep.get("optional", False):
                    activate_dep(dep)
                    key = dep_key(dep)
                    for subfeat in weak_dep_feats.get((pkg_name, key), ()):
                        activate_feat(dep["name"], subfeat)
        else:
            pkg_name, feat = payload
            pkg = packages[pkg_name]
            entries = pkg["features"].get(feat)
            if entries is None:
                activate_opt_dep(pkg_name, feat)
                continue
            for item in entries:
                if item.startswith("dep:"):
                    activate_opt_dep(pkg_name, item[4:])
                elif "?/" in item:
                    dep_name, subfeat = item.split("?/", 1)
                    pair = (pkg_name, dep_name)
                    weak_dep_feats.setdefault(pair, set()).add(subfeat)
                    allow_dev = include_dev and pkg_name == root_pkg
                    for dep in matching_deps(pkg_name, dep_name, allow_dev):
                        if not dep.get("optional", False) or pair in active_opt_deps:
                            activate_feat(dep["name"], subfeat)
                elif "/" in item:
                    dep_name, subfeat = item.split("/", 1)
                    allow_dev = include_dev and pkg_name == root_pkg
                    deps = matching_deps(pkg_name, dep_name, allow_dev)
                    if any(d.get("optional", False) for d in deps):
                        activate_opt_dep(pkg_name, dep_name)
                    for dep in deps:
                        activate_feat(dep["name"], subfeat)
                else:
                    activate_feat(pkg_name, item)

    return active_pkgs


def resolve_external_manifest_deps(packages: dict[str, Any], manifest_path: Path) -> set[str]:
    """Resolve workspace crates reachable from an out-of-workspace Cargo.toml."""
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    closure: set[str] = set()
    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        for dep_key, spec in data.get(section, {}).items():
            if not isinstance(spec, dict) or "path" not in spec:
                continue
            crate_name = spec.get("package", dep_key)
            if crate_name not in packages:
                continue
            use_default = spec.get("default-features", True)
            features = tuple(spec.get("features", ()))
            closure |= resolve_feature_closure(packages, crate_name, use_default, features)
    return closure


def workspace_unified_direct_deps(packages: dict[str, Any]) -> dict[str, set[str]]:
    """Compute each crate's direct workspace deps under unified workspace features."""
    active_feats: set[tuple[str, str]] = set()
    active_opt_deps: set[tuple[str, str]] = set()
    weak_dep_feats: dict[tuple[str, str], set[str]] = {}
    queue: list[tuple[str, str]] = []

    def dep_key(dep: dict[str, Any]) -> str:
        return dep.get("rename") or dep["name"]

    def matching_deps(pkg_name: str, key: str) -> list[dict[str, Any]]:
        return [
            dep
            for dep in packages[pkg_name]["dependencies"]
            if dep["name"] in packages and dep_key(dep) == key
        ]

    def enqueue_feat(pkg_name: str, feat: str) -> None:
        pair = (pkg_name, feat)
        if pair not in active_feats:
            active_feats.add(pair)
            queue.append(pair)

    def activate_dep(dep: dict[str, Any]) -> None:
        target = dep["name"]
        if dep.get("uses_default_features", True) and "default" in packages[target]["features"]:
            enqueue_feat(target, "default")
        for feat in dep.get("features", ()):
            enqueue_feat(target, feat)

    def activate_opt_dep(pkg_name: str, key: str) -> None:
        pair = (pkg_name, key)
        if pair in active_opt_deps:
            return
        active_opt_deps.add(pair)
        for dep in matching_deps(pkg_name, key):
            activate_dep(dep)
            for subfeat in weak_dep_feats.get(pair, ()):
                enqueue_feat(dep["name"], subfeat)

    for name, pkg in packages.items():
        if "default" in pkg["features"]:
            enqueue_feat(name, "default")
        for dep in pkg["dependencies"]:
            if dep["name"] in packages and not dep.get("optional", False):
                activate_dep(dep)

    while queue:
        pkg_name, feat = queue.pop()
        entries = packages[pkg_name]["features"].get(feat)
        if entries is None:
            activate_opt_dep(pkg_name, feat)
            continue
        for item in entries:
            if item.startswith("dep:"):
                activate_opt_dep(pkg_name, item[4:])
            elif "?/" in item:
                dep_name, subfeat = item.split("?/", 1)
                pair = (pkg_name, dep_name)
                weak_dep_feats.setdefault(pair, set()).add(subfeat)
                for dep in matching_deps(pkg_name, dep_name):
                    if not dep.get("optional", False) or pair in active_opt_deps:
                        enqueue_feat(dep["name"], subfeat)
            elif "/" in item:
                dep_name, subfeat = item.split("/", 1)
                deps = matching_deps(pkg_name, dep_name)
                if any(d.get("optional", False) for d in deps):
                    activate_opt_dep(pkg_name, dep_name)
                for dep in deps:
                    enqueue_feat(dep["name"], subfeat)
            else:
                enqueue_feat(pkg_name, item)

    direct: dict[str, set[str]] = {}
    for name, pkg in packages.items():
        deps: set[str] = set()
        for dep in pkg["dependencies"]:
            if dep["name"] not in packages:
                continue
            if not dep.get("optional", False) or (name, dep_key(dep)) in active_opt_deps:
                deps.add(dep["name"])
        direct[name] = deps
    return direct


def reverse_dep_closure(packages: dict[str, Any], changed_crates: set[str]) -> set[str]:
    """Return every workspace crate reachable from changed_crates under workspace unification."""
    direct = workspace_unified_direct_deps(packages)
    affected = set(changed_crates)
    changed = True
    while changed:
        changed = False
        for name, deps in direct.items():
            if name not in affected and (deps & affected):
                affected.add(name)
                changed = True
    return affected


def path_triggers_ultracite(path: str) -> bool:
    """Return True if ultracite (oxfmt/oxlint) formats or lints this path."""
    if path in LINT_CONFIG_FILES:
        return True
    if path in ULTRACITE_IGNORED_FILES or path.startswith(ULTRACITE_IGNORED_PREFIXES):
        return False
    return Path(path).suffix.lower() in ULTRACITE_SUFFIXES


def map_file_to_crate(path: str, dir_to_crate: list[tuple[str, str]]) -> str | None:
    """Return the workspace crate owning path, or None."""
    for crate_dir, crate_name in dir_to_crate:
        if path == crate_dir or path.startswith(crate_dir + "/"):
            return crate_name
    return None


def compute_plan(changed_files: list[str], force_full: bool = False, root: Path = ROOT) -> dict[str, Any]:
    """Compute the full CI execution plan for changed_files."""
    packages = load_workspace_metadata(root)
    matrix_rows = parse_feature_matrix(root)
    bench_targets = parse_bench_targets(root)

    all_crate_names = sorted(packages.keys())
    all_ci_matrix_rows = [r["name"] for r in matrix_rows if r["tier"] == "ci"]
    all_matrix_rows = [r["name"] for r in matrix_rows]
    all_bench_names = [b["target"] for b in bench_targets]

    if force_full:
        return {
            "full": True,
            "rust_fmt": True,
            "fuzz_fmt": True,
            "rust_packages": "--workspace",
            "rust_has_packages": True,
            "matrix_clippy_rows": "full",
            "matrix_test_rows": "ci",
            "check_lib_rows": ",".join(LIB_CHECK_ROWS),
            "fuzz_clippy": True,
            "fuzz_smoke": True,
            "check_nostd": True,
            "check_wasm": True,
            "check_docs": True,
            "package_check": True,
            "doctest_workspace": True,
            "doctest_tcp_smoltcp": True,
            "msrv": True,
            "bench_targets": "all",
            "bench_build": True,
            "relay_container": True,
            "relay_installer": True,
            "docs_site": True,
            "docs_snippets_quickstart": True,
            "docs_snippets_custom_stream": True,
            "ts_lint": True,
            "workflow_tests": True,
            "script_tests": True,
            "bindings_ts": True,
            "bindings_ts_packages": "@minip2p/core @minip2p/node @minip2p/test-fixtures @minip2p/web",
            "bindings_node_native": True,
            "bindings_rn_gen": True,
            "bindings_web": True,
            "bindings_web_e2e": True,
            "summary": "full suite",
        }

    dir_to_crate = sorted(
        ((info["dir"], name) for name, info in packages.items()),
        key=lambda item: len(item[0]),
        reverse=True,
    )

    changed_crates: set[str] = set()
    rust_fmt = False
    fuzz_fmt = False
    fuzz_touched = False
    bench_all = False
    relay_container_direct = False
    relay_installer = False
    docs_site = False
    docs_quickstart_direct = False
    docs_custom_stream_direct = False
    package_check = False
    ts_lint = False
    workflow_tests = False
    script_tests = False
    bindings_node_direct = False
    bindings_rn_direct = False
    bindings_web_direct = False

    for raw_path in changed_files:
        path = raw_path.strip()
        if not path:
            continue

        if path in FULL_TRIGGER_FILES or path.startswith(FULL_TRIGGER_PREFIXES):
            return compute_plan([], force_full=True, root=root)

        if path_triggers_ultracite(path):
            ts_lint = True

        if path.endswith(".rs"):
            if path.startswith("fuzz/"):
                fuzz_fmt = True
            else:
                rust_fmt = True

        if path.endswith("/Cargo.toml") or path.endswith("/README.md") or path == "README.md":
            package_check = True

        if any(path == p or path.startswith(p) for p in WORKFLOW_TEST_PATHS):
            workflow_tests = True

        if path in {"scripts/test_affected.py", "bench/test_bench_results.py", "scripts/bench_results.py"}:
            script_tests = True

        crate = map_file_to_crate(path, dir_to_crate)
        if crate is not None:
            changed_crates.add(crate)
            continue

        if path.startswith("fuzz/"):
            fuzz_touched = True
            continue

        if path.startswith("bench/") or path in BENCH_FILES:
            bench_all = True
            continue

        if path in RELAY_INSTALLER_FILES:
            relay_installer = True
            if path.startswith("docs/"):
                docs_site = True
            continue

        if path.startswith("infra/relay/") or path in RELAY_CONTAINER_FILES:
            relay_container_direct = True
            continue

        if path.startswith("infra/bench/"):
            bench_all = True
            continue

        if path.startswith("docs/snippets/quickstart/"):
            docs_quickstart_direct = True
            docs_site = True
            continue

        if path.startswith("docs/snippets/custom-stream/"):
            docs_custom_stream_direct = True
            docs_site = True
            continue

        if path in NOOP_META_FILES or path.startswith(NOOP_META_PREFIXES):
            continue

        if path.startswith("docs/"):
            docs_site = True
            continue

        if path in TS_CONFIG_FILES:
            bindings_node_direct = True
            bindings_rn_direct = True
            bindings_web_direct = True
            docs_site = True
            continue

        if path in LINT_CONFIG_FILES:
            continue

        if path.startswith("bindings/ts/"):
            if path.startswith("bindings/ts/tests/workflows/"):
                continue
            if path.startswith("bindings/ts/web/"):
                bindings_web_direct = True
            elif path.startswith("bindings/ts/react-native/"):
                bindings_rn_direct = True
            elif path.startswith(("bindings/ts/node/", "bindings/ts/node-platforms/")):
                bindings_node_direct = True
            elif path.startswith(("bindings/ts/core/", "bindings/ts/test-fixtures/", "bindings/ts/scripts/")):
                bindings_node_direct = True
                bindings_rn_direct = True
                bindings_web_direct = True
            else:
                bindings_node_direct = True
                bindings_rn_direct = True
                bindings_web_direct = True
            continue

        if any(path == p or path.startswith(p) for p in WORKFLOW_TEST_PATHS):
            continue

        return compute_plan([], force_full=True, root=root)

    affected_crates = reverse_dep_closure(packages, changed_crates)

    rust_has_packages = bool(affected_crates)
    if not affected_crates:
        rust_packages = ""
    elif len(affected_crates) == len(all_crate_names):
        rust_packages = "--workspace"
    else:
        rust_packages = " ".join(f"-p {name}" for name in sorted(affected_crates))

    matrix_clippy: list[str] = []
    matrix_test: list[str] = []
    check_lib: list[str] = []
    for row in matrix_rows:
        row_crates = resolve_feature_closure(
            packages,
            row["package"],
            use_default=row["default_features"],
            extra_features=row["features"],
            include_dev=True,
        )
        if row_crates & changed_crates:
            matrix_clippy.append(row["name"])
            if row["tier"] == "ci":
                matrix_test.append(row["name"])
            if row["name"] in LIB_CHECK_ROWS:
                check_lib.append(row["name"])

    fuzz_deps = resolve_external_manifest_deps(packages, root / "fuzz" / "Cargo.toml")
    fuzz_needed = fuzz_touched or bool(fuzz_deps & changed_crates)

    nostd_crates: set[str] = set()
    for pkg_name, use_default, feats in NOSTD_ROOTS:
        nostd_crates |= resolve_feature_closure(packages, pkg_name, use_default, feats)
    check_nostd = bool(nostd_crates & changed_crates)

    wasm_crates: set[str] = set()
    for pkg_name, use_default, feats in WASM_ROOTS:
        wasm_crates |= resolve_feature_closure(packages, pkg_name, use_default, feats)
    check_wasm = bool(wasm_crates & changed_crates)

    check_docs = rust_has_packages
    doctest_workspace = rust_has_packages
    tcp_smoltcp_crates = resolve_feature_closure(
        packages, "minip2p-tcp", use_default=True, extra_features=("smoltcp",), include_dev=True
    )
    doctest_tcp_smoltcp = bool(tcp_smoltcp_crates & changed_crates)

    if bench_all:
        selected_benches = all_bench_names
    else:
        selected_benches = []
        for bench in bench_targets:
            bench_crates = resolve_feature_closure(
                packages,
                bench["package"],
                use_default=True,
                extra_features=bench["features"],
                include_dev=True,
            )
            if bench_crates & changed_crates:
                selected_benches.append(bench["target"])

    relay_example_crates = resolve_feature_closure(packages, "minip2p-relay-server-example", use_default=True)
    relay_container = relay_container_direct or bool(relay_example_crates & changed_crates)

    quickstart_deps = resolve_external_manifest_deps(packages, root / "docs" / "snippets" / "quickstart" / "Cargo.toml")
    custom_stream_deps = resolve_external_manifest_deps(
        packages, root / "docs" / "snippets" / "custom-stream" / "Cargo.toml"
    )
    docs_snippets_quickstart = docs_quickstart_direct or bool(quickstart_deps & changed_crates)
    docs_snippets_custom_stream = docs_custom_stream_direct or bool(custom_stream_deps & changed_crates)

    nodejs_crates = resolve_feature_closure(packages, "minip2p-nodejs", use_default=True)
    ffi_crates = resolve_feature_closure(packages, "minip2p-ffi", use_default=True)
    web_crates = resolve_feature_closure(packages, "minip2p-web", use_default=True, include_dev=True)

    bindings_node_tests = bindings_node_direct or bool((nodejs_crates | relay_example_crates) & changed_crates)
    bindings_rn_gen = bindings_rn_direct or bool(ffi_crates & changed_crates)
    bindings_web = bindings_web_direct or bool(web_crates & changed_crates)
    bindings_web_e2e = bindings_web or bindings_node_tests
    bindings_node_native = bindings_node_tests or bindings_web_e2e
    bindings_ts = bindings_node_native or bindings_rn_gen or bindings_web

    ts_pkgs: list[str] = []
    if bindings_node_tests and bindings_web:
        ts_pkgs.extend(["@minip2p/core", "@minip2p/node", "@minip2p/test-fixtures", "@minip2p/web"])
    elif bindings_node_tests:
        ts_pkgs.append("@minip2p/node")
    elif bindings_web:
        ts_pkgs.append("@minip2p/web")
    bindings_ts_packages = " ".join(ts_pkgs)

    matrix_clippy_val = (
        "full" if len(matrix_clippy) == len(all_matrix_rows) else ",".join(matrix_clippy)
    )
    matrix_test_val = (
        "ci" if len(matrix_test) == len(all_ci_matrix_rows) else ",".join(matrix_test)
    )
    bench_targets_val = (
        "all" if len(selected_benches) == len(all_bench_names) else ",".join(selected_benches)
    )

    summary_parts = []
    if affected_crates:
        summary_parts.append(f"crates={len(affected_crates)}/{len(all_crate_names)}")
    if matrix_test:
        summary_parts.append(f"matrix_test={len(matrix_test)}/{len(all_ci_matrix_rows)}")
    if selected_benches:
        summary_parts.append(f"benches={len(selected_benches)}/{len(all_bench_names)}")
    for label, enabled in (
        ("fuzz", fuzz_needed),
        ("relay-container", relay_container),
        ("docs-site", docs_site),
        ("ts-bindings", bindings_web_e2e),
        ("rn-bindings", bindings_rn_gen),
        ("ts-lint", ts_lint),
    ):
        if enabled:
            summary_parts.append(label)
    summary = ", ".join(summary_parts) if summary_parts else "comments-only"

    return {
        "full": False,
        "rust_fmt": rust_fmt,
        "fuzz_fmt": fuzz_fmt,
        "rust_packages": rust_packages,
        "rust_has_packages": rust_has_packages,
        "matrix_clippy_rows": matrix_clippy_val,
        "matrix_test_rows": matrix_test_val,
        "check_lib_rows": ",".join(check_lib),
        "fuzz_clippy": fuzz_needed,
        "fuzz_smoke": fuzz_needed,
        "check_nostd": check_nostd,
        "check_wasm": check_wasm,
        "check_docs": check_docs,
        "package_check": package_check,
        "doctest_workspace": doctest_workspace,
        "doctest_tcp_smoltcp": doctest_tcp_smoltcp,
        "msrv": rust_has_packages,
        "bench_targets": bench_targets_val,
        "bench_build": bool(selected_benches),
        "relay_container": relay_container,
        "relay_installer": relay_installer,
        "docs_site": docs_site,
        "docs_snippets_quickstart": docs_snippets_quickstart,
        "docs_snippets_custom_stream": docs_snippets_custom_stream,
        "ts_lint": ts_lint,
        "workflow_tests": workflow_tests,
        "script_tests": script_tests,
        "bindings_ts": bindings_ts,
        "bindings_ts_packages": bindings_ts_packages,
        "bindings_node_native": bindings_node_native,
        "bindings_rn_gen": bindings_rn_gen,
        "bindings_web": bindings_web,
        "bindings_web_e2e": bindings_web_e2e,
        "summary": summary,
    }


def git_changed_files(base: str, root: Path = ROOT) -> list[str]:
    """Return paths changed between base and HEAD."""
    diff_spec = f"{base}..HEAD" if base == "HEAD^1" else f"{base}...HEAD"
    out = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", diff_spec],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line.strip()]


def format_gh_value(value: Any) -> str:
    """Format a plan value for GITHUB_OUTPUT."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def main(argv: list[str]) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Compute diff-reachable CI targets.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--base", help="Git ref to diff against HEAD (e.g. HEAD^1 or origin/main)")
    group.add_argument("--files", nargs="*", help="Explicit list of changed repo-relative paths")
    group.add_argument("--all", action="store_true", help="Emit the full-suite plan")
    parser.add_argument("--github-output", help="Path to write GitHub Actions outputs")
    args = parser.parse_args(argv)

    if args.all:
        plan = compute_plan([], force_full=True)
    elif args.base is not None:
        files = git_changed_files(args.base)
        plan = compute_plan(files, force_full=False)
    else:
        plan = compute_plan(args.files or [], force_full=False)

    if args.github_output:
        with Path(args.github_output).open("a", encoding="utf-8") as handle:
            for key, value in plan.items():
                handle.write(f"{key}={format_gh_value(value)}\n")

    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
