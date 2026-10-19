// Serves the browser e2e page from `localhost` (a secure context, so
// WebTransport works and Chrome's Local Network Access never prompts),
// with the built `@minip2p/core` and `@minip2p/web` behind an import map.
//
// Usage: node e2e/server.mjs <port>

import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const port = Number(process.argv[2] ?? 4317);
const ts = fileURLToPath(new URL("../../", import.meta.url));
const roots = new Map([
  ["/core/", `${ts}core/`],
  ["/web/", `${ts}web/`],
]);
const types = new Map([
  [".html", "text/html"],
  [".js", "text/javascript"],
  [".map", "application/json"],
  [".wasm", "application/wasm"],
]);

const resolve = (pathname) => {
  if (pathname === "/") {
    return `${ts}web/e2e/page/index.html`;
  }
  for (const [prefix, root] of roots) {
    if (pathname.startsWith(prefix)) {
      const file = path.normalize(`${root}${pathname.slice(prefix.length)}`);
      return file.startsWith(root) ? file : null;
    }
  }
  return null;
};

createServer(async (request, response) => {
  const file = resolve(
    new URL(request.url ?? "/", "http://localhost").pathname
  );
  try {
    if (file === null || file === undefined) {
      throw new Error("not served");
    }
    const body = await readFile(file);
    response.writeHead(200, {
      "content-type":
        types.get(path.extname(file)) ?? "application/octet-stream",
    });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(port, "127.0.0.1");
