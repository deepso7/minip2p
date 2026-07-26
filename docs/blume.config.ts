import { defineConfig } from "blume";

const brand = {
  orange: "oklch(0.610 0.112 47)",
  black: "oklch(0.200 0.008 50)",
  white: "oklch(0.980 0.006 60)",
} as const;

export default defineConfig({
  title: "minip2p",
  description:
    "A minimal, caller-driven libp2p implementation in Rust, built around QUIC and Sans-I/O state machines.",
  logo: {
    image: "/logo.svg",
    text: "minip2p",
  },
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
      logo: "/logo.svg",
      palette: {
        accent: brand.orange,
        background: brand.white,
        foreground: brand.black,
      },
    },
    robots: true,
    sitemap: true,
    structuredData: true,
    x: { creator: "@deepso7", handle: "@deepso7" },
  },
  theme: {
    accent: brand.orange,
    background: {
      light: brand.white,
      dark: brand.black,
    },
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
  deployment: {
    adapter: "cloudflare",
    site: "https://minip2p.com",
  },
});
