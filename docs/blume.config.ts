import { defineConfig } from "blume";
import { cloudflare } from "blume/deploy";
import { filesystem, githubReleases } from "blume/sources";

const brand = {
  black: "oklch(0.170 0.008 250)",
  orange: "oklch(0.610 0.112 47)",
  white: "oklch(0.950 0.006 60)",
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
      { href: "/intro", label: "Docs", path: "/" },
      { label: "Changelog", path: "/changelog" },
    ],
  },
  seo: {
    og: {
      logo: "/logo.svg",
      palette: {
        accent: brand.orange,
        background: brand.white,
        foreground: brand.black,
      },
    },
    x: { creator: "@deepso7", handle: "@deepso7" },
  },
  theme: {
    accent: brand.orange,
    background: {
      dark: brand.black,
      light: brand.white,
    },
    radius: "sm",
  },
  title: "minip2p",
});
