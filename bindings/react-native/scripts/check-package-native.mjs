import { statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const packageRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const requiredArtifacts = [
  'android/src/main/jniLibs/arm64-v8a/libminip2p_ffi.so',
  'android/src/main/jniLibs/x86_64/libminip2p_ffi.so',
  'build/Minip2pFfi.xcframework/ios-arm64/libminip2p_ffi.a',
  'build/Minip2pFfi.xcframework/ios-arm64-simulator/libminip2p_ffi.a',
];

for (const relativePath of requiredArtifacts) {
  const artifact = path.join(packageRoot, relativePath);
  let size;
  try {
    size = statSync(artifact).size;
  } catch {
    throw new Error(
      `Missing ${relativePath}; run pnpm ubrn:android and pnpm ubrn:ios before packaging`
    );
  }
  if (size === 0) {
    throw new Error(`Native package artifact is empty: ${relativePath}`);
  }
}
