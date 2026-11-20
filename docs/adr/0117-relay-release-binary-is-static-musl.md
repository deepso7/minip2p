# The relay release binary is a static musl build, checked for no loader

`scripts/build-relay-release.sh` is the single command both the release workflow and `test-relay-container.sh` use, so the published binary and the tested one come from the same build.

- `musl-gcc` is set only as the C compiler (`CC_<target>`, for ring's and mimalloc's C); the linker stays Rust's default with `+crt-static`, because linking through `musl-gcc` produced a dynamic, crashing binary.
- The script refuses any binary whose ELF headers still have `INTERP` or `NEEDED` entries: a glibc build linked on a newer runner fails to start on older hosts and images. The `readelf` output is captured in a standalone assignment so a `readelf` failure stops the script under `set -e`.
- Releases up to v0.11.0 have only glibc archives (which need glibc 2.39 or newer), so the installer (`docs/public/install/relay.sh`) tries the static musl archive first, then the glibc one; `test-relay-installer.sh` covers that fallback.
