import { defineComponents } from "blume";

// The redesign's replacements for Blume's built-ins. Each keeps the
// built-in's props, so the MDX in `md/` stays as written.
export default defineComponents({
  // The layout shell: no header bar on docs pages (logo and search pin above
  // the sidebar), section tabs atop the content column (the landing page's
  // from PageHeader), and no footer or table of contents.
  layout: {
    Breadcrumbs: "./components/breadcrumbs.astro",
    Footer: "./components/empty.astro",
    Header: "./components/site-header.astro",
    PageHeader: "./components/page-header.astro",
    Sidebar: "./components/sidebar.astro",
    TableOfContents: "./components/empty.astro",
  },
  // Content components in the redesign's quiet style, then the landing page's
  // (`md/index.mdx`) Astro parts. Blume resolves MDX tags from this map, not
  // from imports in the page.
  mdx: {
    Badge: "./components/docs/badge.astro",
    Callout: "./components/docs/callout.astro",
    Card: "./components/docs/card.astro",
    CardGroup: "./components/docs/card-group.astro",
    LandingExample: "./components/landing/example.astro",
    LandingFeatures: "./components/landing/features.astro",
    LandingFoot: "./components/landing/foot.astro",
    Mascot: "./components/mascot.astro",
    Step: "./components/docs/step.astro",
    Steps: "./components/docs/steps.astro",
  },
});
