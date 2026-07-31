import type {
  DriverFailedError,
  Minip2pConfig,
  Unsubscribe,
} from "@minip2p/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { AppState } from "react-native";

import { Minip2p } from "./adapter";
import { bindAppStateSource, mountEndpointLifecycle } from "./hook-lifecycle";

/** Lifecycle state returned by {@link useMinip2p}. */
export type Minip2pHookState =
  | {
      readonly status: "starting";
      readonly endpoint?: undefined;
      readonly peerId?: undefined;
      readonly listenAddrs?: undefined;
      readonly error?: undefined;
    }
  | {
      readonly status: "running";
      readonly endpoint: Minip2p;
      readonly peerId: string;
      readonly listenAddrs: readonly string[];
      readonly error?: undefined;
    }
  | {
      readonly status: "closed";
      readonly endpoint?: undefined;
      readonly peerId?: undefined;
      readonly listenAddrs?: undefined;
      readonly error?: undefined;
    }
  | {
      readonly status: "failed";
      readonly endpoint?: undefined;
      readonly peerId?: undefined;
      readonly listenAddrs?: undefined;
      readonly error: unknown;
    };

/** Hook lifecycle state plus an idempotent endpoint shutdown callback. */
export type UseMinip2pResult = Minip2pHookState & {
  /** Closes the currently owned endpoint, if one exists. */
  readonly close: () => void;
};

/** Mirrors the current and future React Native AppState into an endpoint. */
export const bindAppState = (
  endpoint: Pick<Minip2p, "setActive">
): Unsubscribe => bindAppStateSource(endpoint, AppState);

/**
 * Owns a native endpoint for a committed component lifetime.
 *
 * Keep `createConfig` pure and stable for the component lifetime. Endpoint
 * construction happens only in the committed effect.
 */
export const useMinip2p = (
  createConfig: () => Minip2pConfig
): UseMinip2pResult => {
  const endpointRef = useRef<Minip2p | null>(null);
  const configFactory = useRef(createConfig);
  const [state, setState] = useState<Minip2pHookState>({
    status: "starting",
  });
  const close = useCallback(() => {
    endpointRef.current?.close();
  }, []);

  useEffect(() => {
    const lifecycle = mountEndpointLifecycle({
      bindAppState,
      create: () => {
        const endpoint = Minip2p.create(configFactory.current());
        endpointRef.current = endpoint;
        return endpoint;
      },
      notify: (next) => {
        endpointRef.current = next.status === "running" ? next.endpoint : null;
        setState(next);
      },
    });
    return () => {
      endpointRef.current = null;
      lifecycle.cleanup();
    };
  }, []);

  return { ...state, close };
};

/** Narrows the failed hook state for consumers that want a native failure. */
export const isDriverFailure = (
  state: Minip2pHookState
): state is Extract<Minip2pHookState, { status: "failed" }> & {
  error: DriverFailedError;
} =>
  state.status === "failed" &&
  state.error instanceof Error &&
  state.error.name === "DriverFailedError";
