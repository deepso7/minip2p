import { generateSecretKey, Minip2p } from "@minip2p/node";

const endpoint = Minip2p.create({
  agentVersion: "minip2p-nodejs-example/0.1.0",
  // Each address's shape selects its transport: QUIC first, then TCP.
  listen: ["/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"],
  secretKey: generateSecretKey(),
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    endpoint.close();
    process.exit(0);
  });
}

console.log(`Peer: ${endpoint.peerId()}`);
console.log("Pass either address to the ping script:");
for (const address of endpoint.listenAddrs()) {
  console.log(address);
}
console.log("Press Ctrl+C to stop.");
