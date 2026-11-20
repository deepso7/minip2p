export const initScene = (root: HTMLElement) => {
  if (!("IntersectionObserver" in window)) {
    return;
  }
  const durations = (root.dataset.durations ?? "").split(",").map(Number);
  const last = durations.length;
  const parts = [...root.querySelectorAll<HTMLElement>("[data-show]")];
  const gotos = [...root.querySelectorAll<HTMLElement>("[data-goto]")];
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  let step = 0;
  let timer: number | undefined;
  let remaining = 0;
  let startedAt = 0;
  let autoPaused = false;

  const render = () => {
    root.style.setProperty("--scene-step-ms", `${durations[step - 1] ?? 0}ms`);
    for (const part of parts) {
      const show = Number(part.dataset.show);
      const hide = Number(part.dataset.hide ?? Number.POSITIVE_INFINITY);
      const on = step >= show && step < hide;
      part.toggleAttribute("data-on", on);
      part.toggleAttribute("data-past", on && show < step);
    }
    for (const goto of gotos) {
      const n = Number(goto.dataset.goto);
      if (n < step) {
        goto.dataset.state = "done";
      } else if (n === step) {
        goto.dataset.state = "current";
      } else {
        delete goto.dataset.state;
      }
    }
  };

  const renderFresh = () => {
    for (const el of [...parts, ...gotos]) {
      delete el.dataset.on;
      delete el.dataset.state;
    }
    void root.offsetWidth;
    render();
  };

  const toggle = root.querySelector("[data-toggle]");
  const setMode = (mode: "playing" | "paused" | "ended") => {
    root.toggleAttribute("data-playing", mode === "playing");
    root.toggleAttribute("data-paused", mode === "paused");
    root.toggleAttribute("data-ended", mode === "ended");
    toggle?.setAttribute(
      "aria-label",
      { ended: "Replay", paused: "Play", playing: "Pause" }[mode]
    );
  };

  const schedule = (ms: number) => {
    remaining = ms;
    startedAt = performance.now();
    timer = window.setTimeout(() => {
      timer = undefined;
      if (step < last) {
        step += 1;
        render();
        schedule(durations[step - 1]);
      } else {
        setMode("ended");
      }
    }, ms);
  };

  const stop = () => {
    window.clearTimeout(timer);
    timer = undefined;
  };

  const goTo = (n: number, play: boolean) => {
    stop();
    step = n;
    renderFresh();
    if (play) {
      setMode("playing");
      schedule(durations[step - 1]);
    } else {
      remaining = durations[step - 1];
      setMode(step === last ? "ended" : "paused");
    }
  };

  const pause = () => {
    stop();
    remaining -= performance.now() - startedAt;
    setMode("paused");
  };

  const resume = () => {
    setMode("playing");
    schedule(Math.max(remaining, 0));
  };

  root.toggleAttribute("data-scene-live", true);
  render();

  root.addEventListener("click", (event) => {
    const control = (event.target as Element).closest<HTMLElement>(
      "[data-toggle], [data-goto]"
    );
    if (!control) {
      return;
    }
    autoPaused = false;
    if (control.dataset.goto) {
      goTo(Number(control.dataset.goto), !reducedMotion.matches);
    } else if (Object.hasOwn(root.dataset, "playing")) {
      pause();
    } else if (Object.hasOwn(root.dataset, "paused") && step > 0) {
      resume();
    } else {
      goTo(1, true);
    }
  });

  const stage = root.querySelector("figure") ?? root;
  let seen = false;
  const observer = new IntersectionObserver(
    ([entry]) => {
      if (!entry) {
        return;
      }
      const visible =
        entry.intersectionRatio >= 0.4 ||
        entry.intersectionRect.height >= window.innerHeight * 0.5;
      if (visible && !seen) {
        seen = true;
        goTo(reducedMotion.matches ? last : 1, !reducedMotion.matches);
      } else if (visible && autoPaused) {
        autoPaused = false;
        resume();
      } else if (!visible && Object.hasOwn(root.dataset, "playing")) {
        autoPaused = true;
        pause();
      }
    },
    { threshold: [0, 0.1, 0.2, 0.3, 0.4] }
  );
  observer.observe(stage);

  document.addEventListener(
    "astro:before-swap",
    () => {
      observer.disconnect();
      stop();
    },
    { once: true }
  );
};
