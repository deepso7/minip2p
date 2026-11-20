# Release bumps regenerate version-pinned artifacts and wait long for npm

`scripts/release.sh` treats a version bump as touching more than manifests:

- It regenerates `tests/interop/unified-testing/Cargo.lock`, because that harness's Dockerfile builds with `--locked`, so its pinned minip2p versions must follow the bump.
- It rebuilds the committed web wasm glue (`bindings/ts/web/scripts/build-wasm.mjs`), because wasm-bindgen's import shim names hash the crate version.
- `verify_npm_package` polls the registry for up to 30 minutes: npm can be slow to expose a fresh version, and the ~30 MB `@minip2p/react-native` tarball took about 18 minutes for v0.10.1.
