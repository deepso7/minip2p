import { Minip2p, generateSecretKey } from "@minip2p/web";

/** The echo protocol `minip2p-peer listen` serves. */
const ECHO = "/minip2p/echo/1";
const TIMEOUT = { timeoutMs: 10_000 };

const element = <T extends HTMLElement>(id: string, type: new () => T): T => {
  const found = document.querySelector(`#${id}`);
  if (!(found instanceof type)) {
    throw new TypeError(`missing #${id}`);
  }
  return found;
};
const form = element("connect", HTMLFormElement);
const address = element("address", HTMLInputElement);
const log = element("log", HTMLPreElement);
const print = (line: string): void => {
  log.textContent += `${line}\n`;
};

const node = Minip2p.create({
  protocols: [ECHO],
  secretKey: generateSecretKey(),
});
print(`browser peer ${node.peerId()}`);
node.on("connectionClosed", ({ peerId, reason }) => {
  print(`closed ${peerId}: ${reason.kind}`);
});

const run = async (target: string): Promise<void> => {
  const path = await node.connect(target, TIMEOUT);
  print(`connected to ${path.peerId} (${path.path.kind})`);
  const { protocols } = await node.waitPeerReady(path.peerId, TIMEOUT);
  print(`identified: ${protocols.join(", ")}`);
  print(`ping ${await node.ping(path.peerId, TIMEOUT)} ms`);

  const stream = await node.openStream(path.peerId, ECHO, TIMEOUT);
  await stream.write("hello from the browser");
  stream.closeWrite();
  let echoed = "";
  const decoder = new TextDecoder();
  for await (const chunk of stream) {
    echoed += decoder.decode(chunk, { stream: true });
  }
  print(`echo: ${echoed}`);
};

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await run(address.value.trim());
  } catch (error) {
    print(`failed: ${error instanceof Error ? error.message : String(error)}`);
  }
});
