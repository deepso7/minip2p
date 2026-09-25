// Plays a landing-page scene one step at a time, like a short video.
//
// The markup declares everything; this only moves a step counter:
//   root [data-scene][data-durations="2600,2800"]  one duration (ms) per step
//   [data-show="n"]                 on from step n
//   [data-show="n"][data-hide="m"]  on for steps n to m - 1
//   [data-goto="n"]                 jumps to step n (step list, progress bar)
//   [data-toggle] / [data-restart]  play-pause and replay
// Live parts get `data-on` (plus `data-past` once their step is behind);
// `[data-goto]` gets `data-state="done" | "current"`;
// the root gets `data-playing` or `data-paused`, and `data-ended` at the end.
// Without this script nothing is hidden (see theme.css), so the markup reads
// as the finished frame.
export const initScene = (root: HTMLElement) => {
  const durations = (root.dataset.durations ?? "").split(",").map(Number);
  const last = durations.length;
  const parts = [...root.querySelectorAll<HTMLElement>("[data-show]")];
  const gotos = [...root.querySelectorAll<HTMLElement>("[data-goto]")];
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  let step = 0;
  let timer: number | undefined;
  let remaining = 0;
  let startedAt = 0;
  // Paused by scrolling away rather than by the reader.
  let autoPaused = false;

  const render = () => {
    root.style.setProperty("--scene-step-ms", `${durations[step - 1] ?? 0}ms`);
    for (const part of parts) {
      const show = Number(part.dataset.show);
      const hide = Number(part.dataset.hide ?? Number.POSITIVE_INFINITY);
      const on = step >= show && step < hide;
      part.toggleAttribute("data-on", on);
      // Parts from earlier steps stand finished, so only this step moves.
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

  // A jump replays the target step's motion, so clear every part first and
  // force a reflow before switching the step on again.
  const renderFresh = () => {
    for (const el of [...parts, ...gotos]) {
      delete el.dataset.on;
      delete el.dataset.state;
    }
    void root.offsetWidth;
    render();
  };

  const setMode = (mode: "playing" | "paused" | "ended") => {
    root.toggleAttribute("data-playing", mode === "playing");
    root.toggleAttribute("data-paused", mode === "paused");
    root.toggleAttribute("data-ended", mode === "ended");
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
  // The first frame is the empty stage until the scene is seen.
  render();

  // One listener for every control; each is found by its data attribute.
  root.addEventListener("click", (event) => {
    const control = (event.target as Element).closest<HTMLElement>(
      "[data-toggle], [data-restart], [data-goto]"
    );
    if (!control) {
      return;
    }
    autoPaused = false;
    if (control.dataset.goto) {
      // A jump plays on from that step, like scrubbing a video.
      goTo(Number(control.dataset.goto), true);
    } else if (Object.hasOwn(control.dataset, "restart")) {
      goTo(1, true);
    } else if (Object.hasOwn(root.dataset, "playing")) {
      pause();
    } else if (Object.hasOwn(root.dataset, "paused") && step > 0) {
      resume();
    } else {
      goTo(1, true);
    }
  });

  // Start when the stage itself is on screen (not the step list beside it);
  // pause when it scrolls away and pick up again on return. A stage taller
  // than the viewport (phone landscape) counts once it fills half the screen.
  // A reader who asks for less motion gets the finished frame and steps
  // through it by hand.
  const stage = root.querySelector("figure") ?? root;
  let seen = false;
  new IntersectionObserver(
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
  ).observe(stage);
};
