import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";

const require = createRequire(import.meta.url);
const binding = require("../../minip2p.linux-x64-gnu.node");
const endpoint = new binding.NodeEndpoint(binding.generateSecretKey(), {
  allowUnsigned: false,
  autonatServers: [],
  forceRelay: false,
  protocols: [],
  pubsubRouter: 0,
  quic: { listenAddrs: ["/ip4/127.0.0.1/udp/0/quic-v1"] },
  relays: [],
});

endpoint.start(() => {});
process.stdout.write("started\n");

if (process.argv[2] === "close") {
  const calls = 500;
  const callStarted = performance.now();
  for (let index = 0; index < calls; index += 1) {
    endpoint.connectedPeers();
  }
  const averageCallMs = (performance.now() - callStarted) / calls;
  const closeStarted = performance.now();
  endpoint.close();
  const closeMs = performance.now() - closeStarted;
  process.stdout.write(`averageCallMs=${averageCallMs}\ncloseMs=${closeMs}\n`);
}
