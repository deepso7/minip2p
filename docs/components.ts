import { defineComponents } from "blume";

// The redesign's replacements for Blume's built-ins. Each keeps the
// built-in's props, so the MDX in `md/` stays as written.
export default defineComponents({
  // The layout shell: no header bar on docs pages (logo and search pin above
  // the sidebar), section tabs atop the content column, and no footer.
  layout: {
    Breadcrumbs: "./components/breadcrumbs.astro",
    Footer: "./components/no-footer.astro",
    Header: "./components/site-header.astro",
    Sidebar: "./components/sidebar.astro",
    TableOfContents: "./components/toc.astro",
  },
  // Content components in the redesign's quiet style.
  mdx: {
    Badge: "./components/docs/badge.astro",
    Callout: "./components/docs/callout.astro",
    Card: "./components/docs/card.astro",
    CardGroup: "./components/docs/card-group.astro",
    Step: "./components/docs/step.astro",
    Steps: "./components/docs/steps.astro",
  },
});
