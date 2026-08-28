export const nodePlatforms = [
  { cpu: ["arm64"], os: ["darwin"], target: "darwin-arm64" },
  { cpu: ["x64"], os: ["darwin"], target: "darwin-x64" },
  {
    cpu: ["arm64"],
    libc: ["glibc"],
    os: ["linux"],
    target: "linux-arm64-gnu",
  },
  {
    cpu: ["arm64"],
    libc: ["musl"],
    os: ["linux"],
    target: "linux-arm64-musl",
  },
  {
    cpu: ["x64"],
    libc: ["glibc"],
    os: ["linux"],
    target: "linux-x64-gnu",
  },
  {
    cpu: ["x64"],
    libc: ["musl"],
    os: ["linux"],
    target: "linux-x64-musl",
  },
  { cpu: ["x64"], os: ["win32"], target: "win32-x64-msvc" },
];

export const assertNodePlatformManifest = (manifest, platform) => {
  for (const field of ["os", "cpu", "libc"]) {
    if (JSON.stringify(manifest[field]) !== JSON.stringify(platform[field])) {
      throw new Error(
        `@minip2p/node-${platform.target} has invalid ${field} metadata`
      );
    }
  }

  if (
    manifest.repository?.url !== "git+https://github.com/deepso7/minip2p.git"
  ) {
    throw new Error(
      `@minip2p/node-${platform.target} has invalid repository metadata`
    );
  }
};
