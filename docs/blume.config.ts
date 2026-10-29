import { defineConfig } from "blume";
import { cloudflare } from "blume/deploy";
import { filesystem, githubReleases } from "blume/sources";

const brand = {
  black: "oklch(0.170 0.008 250)",
  orange: "oklch(0.610 0.112 47)",
  white: "oklch(0.950 0.006 60)",
} as const;

// Paper Mono (OFL, fonts/paper-mono/OFL.txt) for every role: body, headings,
// and code. It isn't on Google Fonts, so the site serves its own files.
const paperMono = {
  fallback: "mono",
  name: "Paper Mono",
  variants: [
    { src: "./fonts/paper-mono/PaperMono-Regular.woff2", weight: 400 },
    { src: "./fonts/paper-mono/PaperMono-Medium.woff2", weight: 500 },
    { src: "./fonts/paper-mono/PaperMono-SemiBold.woff2", weight: 600 },
    { src: "./fonts/paper-mono/PaperMono-Bold.woff2", weight: 700 },
    { src: "./fonts/paper-mono/PaperMono-ExtraBold.woff2", weight: 800 },
  ],
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
    fonts: {
      body: paperMono,
      display: paperMono,
      mono: paperMono,
    },
    mode: "dark",
    radius: "none",
  },
  title: "minip2p",
});
