import { defineConfig } from "blume";

export default defineConfig({
  title: "minip2p",
  description:
    "A minimal, caller-driven libp2p implementation in Rust, built around QUIC and Sans-I/O state machines.",
  banner: {
    content: "minip2p is pre-1.0 and not yet published to crates.io.",
    link: {
      text: "Install from GitHub",
      href: "/quickstart/installation",
    },
    dismissible: true,
    id: "minip2p-pre-1.0",
  },
  content: {
    root: "md",
  },
  navigation: {
    sidebar: {
      display: "group",
      items: [
        "/",
        {
          label: "Quickstart",
          items: ["/quickstart/installation", "/quickstart/connect-peers"],
        },
        {
          label: "Core Guides",
          items: [
            "/guides/mental-model",
            "/guides/listen-and-connect",
            "/guides/custom-protocols",
            "/guides/events-and-timeouts",
            "/guides/identity-and-addresses",
          ],
        },
        {
          label: "Network Features",
          items: ["/guides/nat", "/guides/pubsub", "/guides/discovery"],
        },
        {
          label: "Reference",
          items: ["/reference/feature-matrix", "/reference/troubleshooting"],
        },
      ],
    },
  },
  theme: {
    accent: "teal",
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
