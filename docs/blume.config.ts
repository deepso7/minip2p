import { defineConfig } from "blume";

export default defineConfig({
  title: "minip2p",
  description:
    "A minimal, caller-driven libp2p implementation in Rust, built around QUIC and Sans-I/O state machines.",
  banner: {
    content: "minip2p is pre-1.0 and not yet published to crates.io.",
    link: {
      text: "Install from GitHub",
      href: "/quickstart/install",
    },
    dismissible: true,
    id: "minip2p-pre-1.0",
  },
  content: {
    root: "md",
  },
  ai: {
    llmsTxt: {
      enabled: true,
      openapi: false,
    },
  },
  seo: {
    agentReadability: true,
    contentSignals: {
      search: true,
      aiInput: true,
      aiTrain: true,
    },
    og: {
      enabled: true,
      palette: {
        accent: "orange",
      },
    },
    robots: true,
    sitemap: true,
    structuredData: true,
  },
  theme: {
    accent: "orange",
    radius: "sm",
    mode: "system",
  },
  markdown: {
    code: {
      icons: true,
      wrap: false,
    },
  },
  github: {
    owner: "deepso7",
    repo: "minip2p",
    branch: "main",
    dir: "docs",
  },
  lastModified: true,
});
