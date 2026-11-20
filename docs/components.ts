import { defineComponents } from "blume";

export default defineComponents({
  layout: {
    Breadcrumbs: "./components/breadcrumbs.astro",
    Footer: "./components/empty.astro",
    Header: "./components/site-header.astro",
    PageHeader: "./components/page-header.astro",
    Sidebar: "./components/sidebar.astro",
    TableOfContents: "./components/empty.astro",
  },
  mdx: {
    Badge: "./components/docs/badge.astro",
    Callout: "./components/docs/callout.astro",
    Card: "./components/docs/card.astro",
    CardGroup: "./components/docs/card-group.astro",
    LandingConnectionAttempt: "./components/landing/connection-attempt.astro",
    LandingEventLoop: "./components/landing/event-loop.astro",
    LandingExample: "./components/landing/example.astro",
    LandingFeatures: "./components/landing/features.astro",
    LandingFoot: "./components/landing/foot.astro",
    Mascot: "./components/mascot.astro",
    Step: "./components/docs/step.astro",
    Steps: "./components/docs/steps.astro",
  },
});
