/* oxlint-disable no-use-before-define, react/style-prop-object -- Styles conventionally follow the component, and React Native accepts conditional style arrays. */

import type { Minip2p } from "@minip2p/react-native";
import { StatusBar } from "expo-status-bar";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  AppState,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";

import { runSmokeSuite } from "./src/smoke";
import type { SmokeReport, SmokeResult } from "./src/smoke";

export default function App() {
  const endpoints = useRef(new Set<Minip2p>());
  const running = useRef(false);
  const [results, setResults] = useState<SmokeResult[]>([]);
  const [status, setStatus] = useState("ready");

  const run = useCallback(async () => {
    if (running.current) {
      return;
    }
    running.current = true;
    setResults([]);
    setStatus("running");

    const report: SmokeReport = (result) => {
      setResults((current) => [...current, result]);
    };

    try {
      await runSmokeSuite(report, endpoints.current);
      setStatus("passed");
    } catch (error) {
      report({
        detail: error instanceof Error ? error.message : String(error),
        name: "suite",
        passed: false,
      });
      setStatus("failed");
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    const registry = endpoints.current;
    const appState = AppState.addEventListener("change", (state) => {
      const active = state === "active";
      for (const endpoint of registry) {
        endpoint.setActive(active);
      }
    });

    const startTimer = setTimeout(() => {
      void run();
    }, 0);
    return () => {
      clearTimeout(startTimer);
      appState.remove();
      for (const endpoint of registry) {
        endpoint.close();
      }
      registry.clear();
    };
  }, [run]);

  return (
    <SafeAreaView style={styles.safeArea}>
      <ScrollView contentContainerStyle={styles.container}>
        <Text style={styles.eyebrow}>EXPO DEVELOPMENT BUILD</Text>
        <View style={styles.headingRow}>
          <View>
            <Text style={styles.title}>minip2p smoke suite</Text>
            <Text style={styles.subtitle}>
              Real QUIC loopback through Hermes, JSI, C++, UniFFI, and Rust
            </Text>
          </View>
          <View
            style={[
              styles.status,
              status === "passed" && styles.statusPassed,
              status === "failed" && styles.statusFailed,
            ]}
          >
            <Text style={styles.statusText}>{status.toUpperCase()}</Text>
          </View>
        </View>

        <View style={styles.results}>
          {results.length === 0 ? (
            <Text style={styles.empty}>Waiting for the first result…</Text>
          ) : (
            results.map((result, index) => (
              <View key={`${result.name}-${index}`} style={styles.result}>
                <Text style={result.passed ? styles.pass : styles.fail}>
                  {result.passed ? "PASS" : "FAIL"}
                </Text>
                <View style={styles.resultBody}>
                  <Text style={styles.resultName}>{result.name}</Text>
                  {result.detail === undefined ? null : (
                    <Text selectable style={styles.detail}>
                      {result.detail}
                    </Text>
                  )}
                </View>
              </View>
            ))
          )}
        </View>

        <Pressable
          accessibilityRole="button"
          disabled={status === "running"}
          onPress={run}
          style={({ pressed }) => [
            styles.button,
            pressed && styles.buttonPressed,
            status === "running" && styles.buttonDisabled,
          ]}
        >
          <Text style={styles.buttonText}>
            {status === "running" ? "Running…" : "Run again"}
          </Text>
        </Pressable>
      </ScrollView>
      <StatusBar style="dark" />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  button: {
    alignItems: "center",
    backgroundColor: "#171713",
    borderRadius: 12,
    marginTop: 18,
    paddingVertical: 14,
  },
  buttonDisabled: {
    opacity: 0.45,
  },
  buttonPressed: {
    opacity: 0.8,
  },
  buttonText: {
    color: "#fffdf8",
    fontSize: 14,
    fontWeight: "700",
  },
  container: {
    paddingBottom: 40,
    paddingHorizontal: 22,
  },
  detail: {
    color: "#716c5f",
    fontSize: 12,
    lineHeight: 17,
    marginTop: 3,
  },
  empty: {
    color: "#716c5f",
    padding: 18,
  },
  eyebrow: {
    color: "#716c5f",
    fontSize: 11,
    fontWeight: "700",
    letterSpacing: 1.5,
    marginBottom: 8,
    marginTop: 18,
  },
  fail: {
    color: "#a12b2b",
    fontSize: 11,
    fontWeight: "800",
    width: 34,
  },
  headingRow: {
    alignItems: "flex-start",
    flexDirection: "row",
    gap: 12,
    justifyContent: "space-between",
    marginBottom: 24,
  },
  pass: {
    color: "#18753b",
    fontSize: 11,
    fontWeight: "800",
    width: 34,
  },
  result: {
    borderBottomColor: "#ddd7cb",
    borderBottomWidth: StyleSheet.hairlineWidth,
    flexDirection: "row",
    gap: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  resultBody: {
    flex: 1,
  },
  resultName: {
    color: "#171713",
    fontSize: 14,
    fontWeight: "600",
  },
  results: {
    backgroundColor: "#fffdf8",
    borderColor: "#c8c2b5",
    borderRadius: 14,
    borderWidth: StyleSheet.hairlineWidth,
    overflow: "hidden",
  },
  safeArea: {
    backgroundColor: "#f4f1e9",
    flex: 1,
  },
  status: {
    backgroundColor: "#d9d4c8",
    borderRadius: 999,
    marginTop: 5,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  statusFailed: {
    backgroundColor: "#f1bbb5",
  },
  statusPassed: {
    backgroundColor: "#bce5c5",
  },
  statusText: {
    color: "#29271f",
    fontSize: 10,
    fontWeight: "800",
    letterSpacing: 0.7,
  },
  subtitle: {
    color: "#716c5f",
    fontSize: 13,
    lineHeight: 18,
    marginTop: 6,
    maxWidth: 290,
  },
  title: {
    color: "#171713",
    fontSize: 27,
    fontWeight: "700",
  },
});
