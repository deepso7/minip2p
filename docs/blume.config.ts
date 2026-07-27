import { defineConfig } from "blume";

const brand = {
  orange: "oklch(0.610 0.112 47)",
  black: "oklch(0.170 0.008 250)",
  white: "oklch(0.950 0.006 60)",
} as const;

export default defineConfig({
  title: "minip2p",
  description:
    "A minimal, caller-driven libp2p implementation in Rust, built around QUIC and Sans-I/O state machines.",
  logo: {
    image: "/logo.svg",
    text: "minip2p",
  },
  content: {
    sources: [
      {
        type: "filesystem",
        root: "md",
      },
      {
        type: "github-releases",
        prefix: "changelog",
        owner: "deepso7",
        repo: "minip2p",
        limit: 50,
      },
    ],
  },
  navigation: {
    tabs: [
      { label: "Docs", path: "/" },
      { label: "Changelog", path: "/changelog" },
    ],
    sidebar: [
      "/",
      {
        label: "Quickstart",
        items: ["/quickstart/install", "/quickstart/connect-peers"],
      },
      {
        label: "Guides",
        items: [
          "/guides/concepts",
          "/guides/discover-peers",
          "/guides/drive-events",
          "/guides/identity",
          "/guides/listen-and-dial",
          "/guides/pubsub",
          "/guides/register-a-protocol",
          "/guides/traverse-nat",
        ],
      },
      {
        label: "Reference",
        items: [
          "/reference/feature-matrix",
          "/reference/glossary",
          "/reference/troubleshooting",
        ],
      },
      { label: "Changelog", href: "/changelog" },
    ],
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
