#!/usr/bin/env python3
"""Print the workspace's publishable crates in crates.io publish order.

Reads `cargo metadata` and sorts topologically over normal and build
dependencies, optional ones included: crates.io resolves those at publish time.
Dev dependencies are left out because `cargo publish` strips unversioned ones,
so they are never a prerequisite. Ties break alphabetically, so the order only
changes when the dependency graph does. publish.yml publishes in this order.
"""

import json
import subprocess
import sys


def main() -> int:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--no-deps", "--format-version", "1"]
        )
    )
    workspace = {package["name"]: package for package in metadata["packages"]}
    publishable = {
        name for name, package in workspace.items() if package["publish"] != []
    }

    prerequisites = {}
    for name in publishable:
        deps = set()
        for dep in workspace[name]["dependencies"]:
            if dep["kind"] == "dev" or dep["name"] not in workspace:
                continue
            if dep["name"] not in publishable:
                print(
                    f"{name} depends on {dep['name']}, which is not published",
                    file=sys.stderr,
                )
                return 1
            deps.add(dep["name"])
        prerequisites[name] = deps

    published = []
    while prerequisites:
        ready = sorted(
            name for name, deps in prerequisites.items() if deps <= set(published)
        )
        if not ready:
            print(f"dependency cycle among {sorted(prerequisites)}", file=sys.stderr)
            return 1
        published.append(ready[0])
        del prerequisites[ready[0]]

    print("\n".join(published))
    return 0


if __name__ == "__main__":
    sys.exit(main())
