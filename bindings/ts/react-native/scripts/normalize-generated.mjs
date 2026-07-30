/* oxlint-disable func-style -- The recursive normalizer is hoisted below the generated-path manifest. */

import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

const packageRoot = path.resolve(import.meta.dirname, "..");
const generatedPaths = [
  "Minip2p.podspec",
  "react-native.config.js",
  "android/CMakeLists.txt",
  "android/build.gradle",
  "android/cpp-adapter.cpp",
  "android/generated",
  "android/src/main/AndroidManifest.xml",
  "android/src/main/java/com/minip2p/Minip2pModule.kt",
  "android/src/main/java/com/minip2p/Minip2pPackage.kt",
  "cpp/generated",
  "cpp/react-native-minip2p.cpp",
  "cpp/react-native-minip2p.h",
  "ios/Minip2p.h",
  "ios/Minip2p.mm",
  "ios/generated",
  "src/NativeMinip2p.ts",
  "src/generated",
  "src/native.tsx",
];

ensureAndroidMdnsPermissions();
customizeTurboModuleForMdns();

for (const relativePath of generatedPaths) {
  normalizePath(path.join(packageRoot, relativePath));
}

function ensureAndroidMdnsPermissions() {
  const manifest = path.join(
    packageRoot,
    "android/src/main/AndroidManifest.xml"
  );
  if (!existsSync(manifest)) {
    return;
  }
  const source = readFileSync(manifest, "utf-8");
  if (source.includes("android.permission.CHANGE_WIFI_MULTICAST_STATE")) {
    return;
  }
  writeFileSync(
    manifest,
    source.replace(
      "</manifest>",
      `  <uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />
  <uses-permission android:name="android.permission.CHANGE_WIFI_MULTICAST_STATE" />
</manifest>`
    )
  );
}

function customizeTurboModuleForMdns() {
  replaceOnce(
    "src/NativeMinip2p.ts",
    "  cleanupRustCrate(): boolean;\n",
    "  cleanupRustCrate(): boolean;\n  setMdnsEnabled(enabled: boolean): void;\n"
  );
  replaceOnce(
    "android/src/main/java/com/minip2p/Minip2pModule.kt",
    "import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder\n",
    `import com.facebook.react.turbomodule.core.interfaces.CallInvokerHolder
import android.content.Context
import android.net.wifi.WifiManager
`
  );
  replaceOnce(
    "android/src/main/java/com/minip2p/Minip2pModule.kt",
    "  override fun getName(): String {\n",
    `  private var mdnsUsers = 0
  private var multicastLock: WifiManager.MulticastLock? = null

  override fun getName(): String {
`
  );
  replaceOnce(
    "android/src/main/java/com/minip2p/Minip2pModule.kt",
    "  override fun cleanupRustCrate(): Boolean {\n",
    `  @Synchronized
  override fun setMdnsEnabled(enabled: Boolean) {
    if (enabled) {
      mdnsUsers += 1
      if (multicastLock?.isHeld != true) {
        val wifi = reactApplicationContext.applicationContext
          .getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("minip2p-mdns").apply {
          setReferenceCounted(false)
          acquire()
        }
      }
    } else if (mdnsUsers > 0) {
      mdnsUsers -= 1
      if (mdnsUsers == 0) {
        multicastLock?.takeIf { it.isHeld }?.release()
        multicastLock = null
      }
    }
  }

  override fun cleanupRustCrate(): Boolean {
    mdnsUsers = 0
    multicastLock?.takeIf { it.isHeld }?.release()
    multicastLock = null
`
  );
  replaceOnce(
    "ios/Minip2p.mm",
    "    static facebook::jsi::Value __hostFunction_Minip2p_cleanupRustCrate",
    `    static facebook::jsi::Value __hostFunction_Minip2p_setMdnsEnabled(facebook::jsi::Runtime& rt, TurboModule &turboModule, const facebook::jsi::Value* args, size_t count) {
        return facebook::jsi::Value::undefined();
    }
    static facebook::jsi::Value __hostFunction_Minip2p_cleanupRustCrate`
  );
  replaceOnce(
    "ios/Minip2p.mm",
    '            this->methodMap_["cleanupRustCrate"]',
    `            this->methodMap_["setMdnsEnabled"] = MethodMetadata {1, __hostFunction_Minip2p_setMdnsEnabled};
            this->methodMap_["cleanupRustCrate"]`
  );
  replaceOnce(
    "ios/Minip2p.mm",
    "- (NSNumber *)cleanupRustCrate {\n",
    `- (void)setMdnsEnabled:(BOOL)enabled {
}

- (NSNumber *)cleanupRustCrate {
`
  );
}

function replaceOnce(relativePath, needle, replacement) {
  const target = path.join(packageRoot, relativePath);
  if (!existsSync(target)) {
    return;
  }
  const source = readFileSync(target, "utf-8");
  if (source.includes(replacement) || !source.includes(needle)) {
    return;
  }
  writeFileSync(target, source.replace(needle, replacement));
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

  const source = readFileSync(target, "utf-8");
  const normalized = `${source.replaceAll(/[ \t]+$/gmu, "").replace(/\n*$/u, "")}\n`;
  if (normalized !== source) {
    writeFileSync(target, normalized);
  }
}
