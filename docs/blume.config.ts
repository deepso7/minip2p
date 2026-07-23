import { defineConfig } from "blume";

export default defineConfig({
  title: "minip2p",
  description: "Minip2p docs",
  content: {
    sources: [
      { type: "filesystem", root: "md" },
      // Changelog entries from GitHub Releases. Private repos read
      // GITHUB_TOKEN from the environment.
      {
        type: "github-releases",
        owner: "your-org",
        repo: "your-repo",
        prefix: "changelog",
      },
    ],
  },
  github: {
    owner: "deepso7",
    repo: "minip2p",
  },
  lastModified: true,
});
