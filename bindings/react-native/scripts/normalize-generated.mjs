import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const packageRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..'
);
const generatedPaths = [
  'Minip2p.podspec',
  'react-native.config.js',
  'android/CMakeLists.txt',
  'android/build.gradle',
  'android/cpp-adapter.cpp',
  'android/generated',
  'android/src/main/AndroidManifest.xml',
  'android/src/main/java/com/minip2p/Minip2pModule.kt',
  'android/src/main/java/com/minip2p/Minip2pPackage.kt',
  'cpp/generated',
  'cpp/react-native-minip2p.cpp',
  'cpp/react-native-minip2p.h',
  'ios/Minip2p.h',
  'ios/Minip2p.mm',
  'ios/generated',
  'src/NativeMinip2p.ts',
  'src/generated',
  'src/native.tsx',
];

for (const relativePath of generatedPaths) {
  normalizePath(path.join(packageRoot, relativePath));
}

function normalizePath(target) {
  if (!existsSync(target)) {
    return;
  }
  if (statSync(target).isDirectory()) {
    for (const entry of readdirSync(target)) {
      normalizePath(path.join(target, entry));
    }
    return;
  }

  const source = readFileSync(target, 'utf8');
  const normalized = `${source.replace(/[ \t]+$/gm, '').replace(/\n*$/, '')}\n`;
  if (normalized !== source) {
    writeFileSync(target, normalized);
  }
}
