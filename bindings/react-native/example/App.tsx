import { StatusBar } from 'expo-status-bar';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AppState,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { type MiniP2p } from 'react-native-minip2p';

import { runSmokeSuite, type SmokeReport, type SmokeResult } from './src/smoke';

export default function App() {
  const endpoints = useRef(new Set<MiniP2p>());
  const running = useRef(false);
  const [results, setResults] = useState<Array<SmokeResult>>([]);
  const [status, setStatus] = useState('ready');

  const run = useCallback(async () => {
    if (running.current) {
      return;
    }
    running.current = true;
    setResults([]);
    setStatus('running');

    const report: SmokeReport = (result) => {
      setResults((current) => [...current, result]);
    };

    try {
      await runSmokeSuite(report, endpoints.current);
      setStatus('passed');
    } catch (error) {
      report({
        name: 'suite',
        passed: false,
        detail: error instanceof Error ? error.message : String(error),
      });
      setStatus('failed');
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    const registry = endpoints.current;
    const appState = AppState.addEventListener('change', (state) => {
      const active = state === 'active';
      for (const endpoint of registry) {
        endpoint.setActive(active);
      }
    });

    run().catch(() => {});
    return () => {
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
              status === 'passed' && styles.statusPassed,
              status === 'failed' && styles.statusFailed,
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
                  {result.passed ? 'PASS' : 'FAIL'}
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
          disabled={status === 'running'}
          onPress={run}
          style={({ pressed }) => [
            styles.button,
            pressed && styles.buttonPressed,
            status === 'running' && styles.buttonDisabled,
          ]}
        >
          <Text style={styles.buttonText}>
            {status === 'running' ? 'Running…' : 'Run again'}
          </Text>
        </Pressable>
      </ScrollView>
      <StatusBar style="dark" />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#f4f1e9',
  },
  container: {
    paddingHorizontal: 22,
    paddingBottom: 40,
  },
  eyebrow: {
    marginTop: 18,
    marginBottom: 8,
    color: '#716c5f',
    fontSize: 11,
    fontWeight: '700',
    letterSpacing: 1.5,
  },
  headingRow: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    justifyContent: 'space-between',
    gap: 12,
    marginBottom: 24,
  },
  title: {
    color: '#171713',
    fontSize: 27,
    fontWeight: '700',
  },
  subtitle: {
    maxWidth: 290,
    marginTop: 6,
    color: '#716c5f',
    fontSize: 13,
    lineHeight: 18,
  },
  status: {
    marginTop: 5,
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 6,
    backgroundColor: '#d9d4c8',
  },
  statusPassed: {
    backgroundColor: '#bce5c5',
  },
  statusFailed: {
    backgroundColor: '#f1bbb5',
  },
  statusText: {
    color: '#29271f',
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.7,
  },
  results: {
    overflow: 'hidden',
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#c8c2b5',
    borderRadius: 14,
    backgroundColor: '#fffdf8',
  },
  empty: {
    padding: 18,
    color: '#716c5f',
  },
  result: {
    flexDirection: 'row',
    gap: 12,
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderBottomWidth: StyleSheet.hairlineWidth,
    borderBottomColor: '#ddd7cb',
  },
  pass: {
    width: 34,
    color: '#18753b',
    fontSize: 11,
    fontWeight: '800',
  },
  fail: {
    width: 34,
    color: '#a12b2b',
    fontSize: 11,
    fontWeight: '800',
  },
  resultBody: {
    flex: 1,
  },
  resultName: {
    color: '#171713',
    fontSize: 14,
    fontWeight: '600',
  },
  detail: {
    marginTop: 3,
    color: '#716c5f',
    fontSize: 12,
    lineHeight: 17,
  },
  button: {
    alignItems: 'center',
    marginTop: 18,
    borderRadius: 12,
    paddingVertical: 14,
    backgroundColor: '#171713',
  },
  buttonPressed: {
    opacity: 0.8,
  },
  buttonDisabled: {
    opacity: 0.45,
  },
  buttonText: {
    color: '#fffdf8',
    fontSize: 14,
    fontWeight: '700',
  },
});
