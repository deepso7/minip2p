export const nodePlatforms = [
  { target: "darwin-arm64", os: ["darwin"], cpu: ["arm64"] },
  { target: "darwin-x64", os: ["darwin"], cpu: ["x64"] },
  {
    target: "linux-arm64-gnu",
    os: ["linux"],
    cpu: ["arm64"],
    libc: ["glibc"],
  },
  {
    target: "linux-arm64-musl",
    os: ["linux"],
    cpu: ["arm64"],
    libc: ["musl"],
  },
  {
    target: "linux-x64-gnu",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["glibc"],
  },
  {
    target: "linux-x64-musl",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["musl"],
  },
  { target: "win32-x64-msvc", os: ["win32"], cpu: ["x64"] },
];

export function assertNodePlatformManifest(manifest, platform) {
  for (const field of ["os", "cpu", "libc"]) {
    if (JSON.stringify(manifest[field]) !== JSON.stringify(platform[field])) {
      throw new Error(
        `@minip2p/node-${platform.target} has invalid ${field} metadata`
      );
    }
  }
}
