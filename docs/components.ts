import { defineComponents } from "blume";

// The terminal direction's replacements for Blume's built-ins. Each keeps the
// built-in's props, so the MDX in `md/` stays as written.
export default defineComponents({
  layout: {
    Footer: "./components/status-bar.astro",
  },
  mdx: {
    Callout: "./components/docs/callout.astro",
    Card: "./components/docs/card.astro",
    CardGroup: "./components/docs/card-group.astro",
    Step: "./components/docs/step.astro",
    Steps: "./components/docs/steps.astro",
  },
});
