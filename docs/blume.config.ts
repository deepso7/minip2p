import { defineConfig } from "blume";
import { cloudflare } from "blume/deploy";
import { filesystem, githubReleases } from "blume/sources";

// Brand colours, matching the tokens in theme.css: warm paper and blue-black
// ink, with the orange accent printed darker on paper and lit amber on ink.
const brand = {
  amber: "oklch(0.770 0.135 60)",
  ink: "oklch(0.155 0.006 250)",
  orange: "oklch(0.540 0.130 42)",
  paper: "oklch(0.955 0.006 60)",
} as const;

export default defineConfig({
  content: {
    sources: [
      filesystem({ root: "md" }),
      githubReleases({
        limit: 50,
        owner: "deepso7",
        prefix: "changelog",
        repo: "minip2p",
      }),
    ],
  },
  deployment: cloudflare({ output: "static", site: "https://minip2p.com" }),
  description:
    "A minimal, caller-driven libp2p implementation in Rust, built around QUIC and Sans-I/O state machines.",
  github: {
    dir: "docs",
    owner: "deepso7",
    repo: "minip2p",
  },
  lastModified: "git",
  logo: {
    image: "/logo.svg",
    text: "minip2p",
  },
  navigation: {
    tabs: [
      { href: "/docs/intro", label: "Docs", path: "/docs" },
      { label: "Changelog", path: "/changelog" },
    ],
  },
  // The docs lived at the site root until the landing page took it over.
  redirects: [
    { from: "/docs", to: "/docs/intro" },
    { from: "/intro", to: "/docs/intro" },
    { from: "/rust/:slug*", to: "/docs/rust/:slug*" },
    { from: "/typescript/:slug*", to: "/docs/typescript/:slug*" },
    { from: "/reference/:slug*", to: "/docs/reference/:slug*" },
  ],
  seo: {
    og: {
      logo: "/logo.svg",
      palette: {
        accent: brand.orange,
        background: brand.paper,
        foreground: brand.ink,
      },
    },
    x: { creator: "@deepso7", handle: "@deepso7" },
  },
  theme: {
    accent: { dark: brand.amber, light: brand.orange },
    background: { dark: brand.ink, light: brand.paper },
    fonts: { body: "geist", display: "geist", mono: "geist-mono" },
    mode: "system",
    radius: "md",
  },
  title: "minip2p",
});
