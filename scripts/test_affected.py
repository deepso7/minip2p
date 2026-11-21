#!/usr/bin/env python3
"""Unit tests for scripts/affected.py."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

import affected

ROOT = Path(__file__).resolve().parent.parent


def cargo_tree_workspace_crates(
    package: str, use_default: bool = True, features: tuple[str, ...] = ()
) -> set[str]:
    """Return workspace crates reported by `cargo tree` for normal+build edges."""
    cmd = ["cargo", "tree", "-p", package, "--edges", "normal,build", "--prefix", "none", "--format", "{p}"]
    if not use_default:
        cmd.append("--no-default-features")
    if features:
        cmd.extend(["--features", ",".join(features)])
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=True).stdout
    workspace_names = set(affected.load_workspace_metadata(ROOT).keys())
    found = set()
    for line in out.splitlines():
        name = line.strip().split(" ", 1)[0]
        if name in workspace_names:
            found.add(name)
    return found


class AffectedPlanTest(unittest.TestCase):
    """Verify feature-aware reachability and fail-open behavior."""

    def test_docs_markdown_skips_rust_and_bindings(self) -> None:
        plan = affected.compute_plan(["docs/md/index.mdx"])
        self.assertFalse(plan["full"])
        self.assertTrue(plan["docs_site"])
        self.assertTrue(plan["ts_lint"])
        self.assertFalse(plan["docs_snippets_quickstart"])
        self.assertFalse(plan["docs_snippets_custom_stream"])
        self.assertFalse(plan["rust_has_packages"])
        self.assertFalse(plan["msrv"])
        self.assertFalse(plan["relay_container"])
        self.assertFalse(plan["fuzz_smoke"])
        self.assertFalse(plan["bench_build"])
        self.assertFalse(plan["bindings_ts"])

    def test_adr_only_skips_blume_and_rust(self) -> None:
        plan = affected.compute_plan(["docs/adr/0120-std-tcp-yamux-receive-window.md"])
        self.assertFalse(plan["docs_site"])
        self.assertTrue(plan["ts_lint"])
        self.assertFalse(plan["rust_has_packages"])
        self.assertFalse(plan["bindings_ts"])

    def test_single_leaf_example_only_tests_itself(self) -> None:
        plan = affected.compute_plan(["examples/mdns/src/main.rs"])
        self.assertEqual(plan["rust_packages"], "-p minip2p-mdns-demo")
        self.assertTrue(plan["rust_fmt"])
        self.assertTrue(plan["msrv"])
        self.assertEqual(plan["matrix_test_rows"], "")
        self.assertEqual(plan["matrix_clippy_rows"], "")
        self.assertFalse(plan["fuzz_smoke"])
        self.assertFalse(plan["relay_container"])
        self.assertFalse(plan["bench_build"])
        self.assertFalse(plan["bindings_ts"])
        self.assertFalse(plan["check_nostd"])
        self.assertFalse(plan["check_wasm"])

    def test_tcp_transport_skips_web_fuzz_and_quic_snippets(self) -> None:
        plan = affected.compute_plan(["transports/tcp/src/lib.rs"])
        self.assertTrue(plan["rust_has_packages"])
        self.assertIn("-p minip2p-tcp", plan["rust_packages"])
        self.assertNotIn("-p minip2p-quic", plan["rust_packages"])
        self.assertTrue(plan["relay_container"])
        self.assertTrue(plan["bench_build"])
        self.assertFalse(plan["fuzz_smoke"])
        self.assertFalse(plan["check_wasm"])
        self.assertFalse(plan["bindings_web"])
        self.assertTrue(plan["bindings_node_native"])
        self.assertFalse(plan["docs_snippets_quickstart"])
        self.assertTrue(plan["doctest_tcp_smoltcp"])

    def test_discovery_skips_relay_container_and_web(self) -> None:
        plan = affected.compute_plan(["crates/discovery/src/lib.rs"])
        self.assertIn("-p minip2p-discovery", plan["rust_packages"])
        self.assertTrue(plan["fuzz_smoke"])
        self.assertTrue(plan["bench_build"])
        self.assertIn("peer_book_ir", plan["bench_targets"].split(","))
        self.assertFalse(plan["relay_container"])
        self.assertFalse(plan["bindings_web"])
        self.assertFalse(plan["check_wasm"])
        self.assertTrue(plan["check_nostd"])

    def test_web_binding_only_runs_web_and_skips_rust_and_rn(self) -> None:
        plan = affected.compute_plan(["bindings/ts/web/src/index.ts"])
        self.assertFalse(plan["rust_has_packages"])
        self.assertTrue(plan["bindings_ts"])
        self.assertEqual(plan["bindings_ts_packages"], "@minip2p/web")
        self.assertTrue(plan["bindings_web"])
        self.assertTrue(plan["bindings_web_e2e"])
        self.assertTrue(plan["bindings_node_native"])
        self.assertFalse(plan["bindings_rn_gen"])
        self.assertFalse(plan["bindings_rn_built"])
        self.assertFalse(plan["relay_container"])
        self.assertFalse(plan["fuzz_smoke"])

    def test_relay_server_reaches_minip2p_rs_in_workspace_tests(self) -> None:
        plan = affected.compute_plan(["crates/relay-server/src/lib.rs"])
        self.assertIn("-p minip2p-relay-server", plan["rust_packages"])
        self.assertIn("-p minip2p-rs", plan["rust_packages"])
        self.assertIn("-p minip2p-relay-server-example", plan["rust_packages"])
        self.assertNotIn("-p minip2p-quic", plan["rust_packages"])
        self.assertTrue(plan["relay_container"])
        self.assertFalse(plan["bindings_web"])

    def test_react_native_ts_skips_playwright(self) -> None:
        plan = affected.compute_plan(["bindings/ts/react-native/src/index.ts"])
        self.assertTrue(plan["bindings_ts"])
        self.assertEqual(plan["bindings_ts_packages"], "@minip2p/core @minip2p/react-native")
        self.assertTrue(plan["bindings_rn_gen"])
        self.assertTrue(plan["bindings_rn_built"])
        self.assertFalse(plan["bindings_web"])
        self.assertFalse(plan["bindings_web_e2e"])
        self.assertFalse(plan["bindings_node_native"])
        self.assertFalse(plan["rust_has_packages"])

    def test_ts_scripts_enable_full_binding_prerequisites(self) -> None:
        plan = affected.compute_plan(["bindings/ts/scripts/module-exports.mjs"])
        self.assertEqual(plan["bindings_ts_packages"], "all")
        self.assertTrue(plan["bindings_node_native"])
        self.assertTrue(plan["bindings_web"])
        self.assertTrue(plan["bindings_web_e2e"])
        self.assertTrue(plan["bindings_rn_gen"])
        self.assertTrue(plan["bindings_rn_built"])

    def test_node_platform_manifest_triggers_workflow_tests(self) -> None:
        plan = affected.compute_plan(["bindings/ts/node-platforms/x86_64-unknown-linux-gnu/package.json"])
        self.assertTrue(plan["workflow_tests"])
        self.assertTrue(plan["bindings_ts"])
        self.assertFalse(plan["bindings_rn_gen"])

    def test_root_manifest_and_unknown_paths_fail_open(self) -> None:
        self.assertTrue(affected.compute_plan(["Cargo.lock"])["full"])
        self.assertTrue(affected.compute_plan(["scripts/affected.py"])["full"])
        self.assertTrue(affected.compute_plan(["some-new-top-level/file.txt"])["full"])

    def test_feature_resolver_matches_cargo_tree(self) -> None:
        packages = affected.load_workspace_metadata(ROOT)
        cases = [
            ("minip2p-relay-server-example", True, ()),
            ("minip2p-web", True, ()),
            ("minip2p-web", False, ()),
            ("minip2p-nodejs", True, ()),
            ("minip2p-ffi", True, ()),
            ("minip2p-rs", False, ("smoltcp", "pubsub")),
            ("minip2p-rs", False, ("std", "tcp", "relay-server")),
        ]
        for package, use_default, features in cases:
            with self.subTest(package=package, use_default=use_default, features=features):
                resolved = affected.resolve_feature_closure(packages, package, use_default, features)
                expected = cargo_tree_workspace_crates(package, use_default, features)
                self.assertEqual(resolved, expected)


if __name__ == "__main__":
    unittest.main()
