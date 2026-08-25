/* oxlint-disable class-methods-use-this, no-empty-function, node/callback-return, promise/prefer-await-to-callbacks, unicorn/no-useless-spread -- Lifecycle fakes deliberately model callback registration and inert cleanup. */

import assert from "node:assert/strict";

export const verifyHookLifecycle = ({
  bindAppStateSource,
  ClosedError,
  mountEndpointLifecycle,
}) => {
  class FakeEndpoint {
    closeHandlers = new Set();
    log = [];
    closed = false;

    close() {
      this.closed = true;
      this.log.push("close");
    }

    listenAddrs() {
      return ["/test"];
    }

    onClose(handler) {
      this.closeHandlers.add(handler);
      return () => {
        this.log.push("unbindClose");
        this.closeHandlers.delete(handler);
      };
    }

    peerId() {
      return "peer";
    }

    setActive(active) {
      if (this.closed) {
        throw new ClosedError();
      }
      this.log.push(["active", active]);
    }

    terminal(reason) {
      this.closed = true;
      for (const handler of [...this.closeHandlers]) {
        handler(reason);
      }
    }
  }

  {
    const endpoint = new FakeEndpoint();
    let handler;
    let removed = false;
    const source = {
      addEventListener(_type, next) {
        handler = next;
        return {
          remove() {
            removed = true;
          },
        };
      },
      currentState: "background",
    };
    const unbind = bindAppStateSource(endpoint, source);
    handler("active");
    unbind();

    assert.deepEqual(endpoint.log, [
      ["active", false],
      ["active", true],
    ]);
    assert.equal(removed, true);
  }

  {
    const endpoint = new FakeEndpoint();
    let handler;
    let removed = false;
    const source = {
      addEventListener(_type, next) {
        handler = next;
        return {
          remove() {
            removed = true;
          },
        };
      },
      currentState: "active",
    };
    bindAppStateSource(endpoint, source);
    endpoint.closed = true;

    assert.doesNotThrow(() => handler("background"));
    assert.equal(removed, true);
  }

  {
    const endpoint = new FakeEndpoint();
    const scheduled = [];
    const states = [];
    const lifecycle = mountEndpointLifecycle({
      bindAppState() {
        return () => endpoint.log.push("unbindAppState");
      },
      create: () => endpoint,
      notify: (state) => states.push(state),
      schedule: (callback) => scheduled.push(callback),
    });
    endpoint.terminal({ reason: "close" });
    for (const callback of scheduled) {
      callback();
    }
    lifecycle.cleanup();

    assert.deepEqual(states, [{ status: "closed" }]);
    assert.deepEqual(endpoint.log, ["unbindAppState", "unbindClose"]);
  }

  {
    const endpoint = new FakeEndpoint();
    const driverStates = [];
    mountEndpointLifecycle({
      bindAppState: () => () => {},
      create: () => endpoint,
      notify: (state) => driverStates.push(state),
      schedule: () => {},
    });
    const failure = new Error("driver failed");
    endpoint.terminal({ error: failure, reason: "driverFailed" });
    assert.deepEqual(driverStates, [{ error: failure, status: "failed" }]);

    const createStates = [];
    const createFailure = new Error("create failed");
    mountEndpointLifecycle({
      bindAppState: () => () => {},
      create() {
        throw createFailure;
      },
      notify: (state) => createStates.push(state),
      schedule: (callback) => callback(),
    });
    assert.deepEqual(createStates, [
      { error: createFailure, status: "failed" },
    ]);
  }

  {
    const endpoint = new FakeEndpoint();
    const states = [];
    const lifecycle = mountEndpointLifecycle({
      bindAppState() {
        return () => endpoint.log.push("unbindAppState");
      },
      create: () => endpoint,
      notify: (state) => states.push(state),
      schedule: (callback) => callback(),
    });
    lifecycle.cleanup();

    assert.equal(states[0].status, "running");
    assert.equal(states[0].endpoint, endpoint);
    assert.equal(states[0].peerId, "peer");
    assert.deepEqual(states[0].listenAddrs, ["/test"]);
    assert.deepEqual(endpoint.log, ["unbindClose", "unbindAppState", "close"]);
  }
};
