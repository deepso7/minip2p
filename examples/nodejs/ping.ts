import { generateSecretKey, Minip2p } from "@minip2p/node";

const address = process.argv.at(2);
if (!address || process.argv.length !== 3) {
  throw new Error(
    "Usage: pnpm run ping <multiaddress printed by the listener>"
  );
}

const endpoint = Minip2p.create({
  agentVersion: "minip2p-nodejs-example/0.1.0",
  // Bind both transports so either printed listener address can be dialed.
  listen: ["/ip4/127.0.0.1/udp/0/quic-v1", "/ip4/127.0.0.1/tcp/0"],
  secretKey: generateSecretKey(),
});

try {
  const connected = await endpoint.connect(address, { timeoutMs: 10_000 });
  await endpoint.waitPeerReady(connected.peerId, { timeoutMs: 10_000 });
  const rttMs = await endpoint.ping(connected.peerId, { timeoutMs: 5000 });

  console.log(`Connected to ${connected.peerId} over ${connected.path.kind}`);
  console.log(`Ping: ${rttMs} ms`);
} finally {
  endpoint.close();
}
