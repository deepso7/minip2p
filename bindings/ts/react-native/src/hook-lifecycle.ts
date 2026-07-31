/* oxlint-disable promise/prefer-await-to-callbacks -- This module coordinates synchronous lifecycle callbacks. */

import type { CloseReason, Unsubscribe } from "@minip2p/core";

export interface HookEndpoint {
  close: () => void;
  listenAddrs: () => readonly string[];
  onClose: (handler: (reason: CloseReason) => void) => Unsubscribe;
  peerId: () => string;
  setActive: (active: boolean) => void;
}

export interface AppStateSource {
  readonly currentState: string | null | undefined;
  addEventListener: (
    type: "change",
    handler: (state: string) => void
  ) => { remove: () => void };
}

/** @internal */
export const bindAppStateSource = (
  endpoint: Pick<HookEndpoint, "setActive">,
  source: AppStateSource
): Unsubscribe => {
  endpoint.setActive(source.currentState === "active");
  const subscription = source.addEventListener("change", (state) => {
    endpoint.setActive(state === "active");
  });
  return () => {
    subscription.remove();
  };
};

export type LifecycleState<Endpoint extends HookEndpoint> =
  | {
      readonly status: "running";
      readonly endpoint: Endpoint;
      readonly peerId: string;
      readonly listenAddrs: readonly string[];
    }
  | { readonly status: "closed" }
  | { readonly status: "failed"; readonly error: unknown };

/** @internal */
export const mountEndpointLifecycle = <Endpoint extends HookEndpoint>(options: {
  readonly bindAppState: (endpoint: Endpoint) => Unsubscribe;
  readonly create: () => Endpoint;
  readonly notify: (state: LifecycleState<Endpoint>) => void;
  readonly schedule?: (callback: () => void) => void;
}): { readonly close: () => void; readonly cleanup: () => void } => {
  const schedule = options.schedule ?? ((callback) => setTimeout(callback, 0));
  let active = true;
  let generation = 0;
  let endpoint: Endpoint | undefined;
  let removeClose: Unsubscribe | undefined;
  let removeAppState: Unsubscribe | undefined;

  try {
    const created = options.create();
    endpoint = created;
    removeClose = created.onClose((reason) => {
      if (!active) {
        return;
      }
      generation += 1;
      removeAppState?.();
      removeAppState = undefined;
      endpoint = undefined;
      options.notify(
        reason.reason === "driverFailed"
          ? { error: reason.error, status: "failed" }
          : { status: "closed" }
      );
    });
    const unbindAppState = options.bindAppState(created);
    if (endpoint === created) {
      removeAppState = unbindAppState;
    } else {
      unbindAppState();
    }
    const running = {
      endpoint: created,
      listenAddrs: created.listenAddrs(),
      peerId: created.peerId(),
      status: "running" as const,
    };
    const scheduledGeneration = generation;
    schedule(() => {
      if (
        active &&
        generation === scheduledGeneration &&
        endpoint === created
      ) {
        options.notify(running);
      }
    });
  } catch (error) {
    removeClose?.();
    removeClose = undefined;
    removeAppState?.();
    removeAppState = undefined;
    endpoint?.close();
    endpoint = undefined;
    const scheduledGeneration = generation;
    schedule(() => {
      if (active && generation === scheduledGeneration) {
        options.notify({ error, status: "failed" });
      }
    });
  }

  return {
    cleanup: () => {
      active = false;
      generation += 1;
      removeClose?.();
      removeClose = undefined;
      removeAppState?.();
      removeAppState = undefined;
      const current = endpoint;
      endpoint = undefined;
      current?.close();
    },
    close: () => {
      endpoint?.close();
    },
  };
};
