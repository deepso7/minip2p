# Relay-server host

The default application path is the same three calls as any other endpoint:

```rust
let endpoint = Endpoint::builder()
    .relay_server()
    .listen_on("/ip4/0.0.0.0/udp/19876/quic-v1")?
    .bind()?;
```

Run the included operational host to serve QUIC and TCP on both address families with production defaults:

```bash
cargo run -p minip2p-relay-server-example
```

Linux release archives are also available for x86-64 and ARM64 from the [GitHub Releases page](https://github.com/deepso7/minip2p/releases). Download the archive for your machine together with `SHA256SUMS`, verify it, and install the executable:

```bash
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf minip2p-relay-server-v*-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 0755 \
  minip2p-relay-server-v*-x86_64-unknown-linux-gnu/minip2p-relay \
  /usr/local/bin/
minip2p-relay --version
```

Use `aarch64-unknown-linux-gnu` instead on an ARM64 host. Running `minip2p-relay` with no options starts the same dual-stack listener as the Cargo command above.

On a Linux systemd host with standard administration tools under `/usr/bin` and `/usr/sbin`, install and start the service with one command:

```bash
sudo minip2p-relay service install --hostname relay.example.com
```

The command keeps the identity under `/var/lib/minip2p-relay`. Run `minip2p-relay service status` or `minip2p-relay service logs` to inspect it.

The executable expands the same builder when composing all four listeners:

```rust
let endpoint = Endpoint::builder()
    .relay_server()
    .listen_on("/ip4/0.0.0.0/udp/19876/quic-v1")?
    .listen_on("/ip6/::/udp/19876/quic-v1")?
    .listen_on("/ip4/0.0.0.0/tcp/19876")?
    .listen_on("/ip6/::/tcp/19876")?
    .bind()?;
```

The executable tries both transports on IPv4 and IPv6 port `19876`, falling back to whichever address family is available. It prints dialable addresses with its peer identity and renders typed reservation/circuit lifecycle events, directional byte totals, denial statuses, close causes, and operational errors, including an address refresh it rejected (`AddrsRejected`, after which it keeps advertising the previous addresses) and the refresh that restores it (`AddrsRestored`). Type `pause` or `resume` on stdin to change admission without removing HOP from Identify or terminating existing reservations and circuits.

Use repeatable `--quic` and `--tcp` flags to replace automatic binds with exact `HOST:PORT` socket addresses. A hostname binds its first resolved address; repeat the flag with each family's address to bind both. The relay turns each address into its `listen_on` multiaddr:

```bash
cargo run -p minip2p-relay-server-example -- \
  --quic 192.0.2.10:4101 --quic '[2001:db8::10]:4101' \
  --tcp 192.0.2.10:4201 --tcp '[2001:db8::10]:4201'
```

Add `--webtransport` to serve browsers too: each QUIC socket also listens on `…/quic-v1/webtransport`, and the relay prints the address a browser dials, certhash included, as `[relay] webtransport=/ip4/…/udp/19876/quic-v1/webtransport/certhash/u…/p2p/…`. The certhash pins the relay's current WebTransport certificate. That certificate is derived from the relay's key, so it survives restarts with `--key`, but it rotates every 13 days, so an address with a certhash goes stale within about 26 days. For one permanent address, give the relay a CA-signed certificate (see [Browsers with a stable address](#browsers-with-a-stable-address)).

For a stable public identity and explicit advertised addresses:

```bash
cargo run -p minip2p-relay-server-example -- \
  --key var/relay.ed25519 \
  --announce /dns4/relay.example.com/tcp/19876 \
  --announce /dns4/relay.example.com/udp/19876/quic-v1
```

The key file is created owner-only on Unix and never overwritten. Configuration and address errors are reported before transport binding where possible. Run with `--help` for capacity (overall, per peer, and per IPv4 address or IPv6 /64), duration, byte, pending-control, timeout, and fixed peer/IP token-bucket flags, plus `--max-rate-limit-entries` for the keys each token-bucket map tracks. A rate flag accepts `CAPACITY/REFILL_MS` or `off`. Zero circuit duration/bytes mean unlimited; zero capacities deny new work.

Explicit announce addresses are trusted operator input and take precedence over AutoNAT-confirmed direct addresses and concrete listeners. TCP, QUIC-v1 and WebTransport shapes are accepted. Without `--webtransport-cert`, a WebTransport one must carry its `/certhash` (copy it from the `webtransport=` line); with it, a WebTransport one must not. Wildcards, circuit addresses, other shapes, and conflicting `/p2p` identities are rejected.

## Browsers with a stable address

With a domain and a CA-signed certificate, browsers dial a permanent address with no `/certhash`, such as `/dns/relay.example.com/udp/19876/quic-v1/webtransport/p2p/12D3KooW…`, and check the certificate the way they check any HTTPS page:

```bash
minip2p-relay --key var/relay.ed25519 \
  --webtransport-cert fullchain.pem --webtransport-key privkey.pem \
  --announce /dns/relay.example.com/udp/19876/quic-v1/webtransport
```

`--webtransport-cert` (the PEM chain, leaf first) and `--webtransport-key` (its PEM private key) come together and imply `--webtransport`. The relay reads both files before binding, refuses a key that doesn't match the leaf or a leaf that has expired, and prints each announced `[relay] webtransport=/dns/…` address and the leaf's `webtransport_certificate_not_after=`. The certificate names a domain, so the listener's IP addresses are not printed as `webtransport=` lines. It checks both files' modification times every 30 seconds (`--webtransport-reload-secs`) and serves a renewed certificate to new connections without a restart, so reservations and circuits survive a renewal; it logs `[relay] webtransport certificate reloaded not_after=…`. If the new files don't load (unreadable, a key that doesn't match the leaf, an expired leaf), it logs why on stderr and keeps serving the previous certificate until either file changes again. At startup, after each reload, and then daily, it logs `[relay] warning: the WebTransport certificate expires in N days` once the leaf has fewer than 14 days left; point log alerting at that line, because Let's Encrypt no longer emails expiry notices.

On a systemd host with certbot, for `relay.example.com` (also on the docs site as [Stable browser addresses](https://minip2p.com/rust/webtransport-certificates)):

1. Open TCP port 80 for the HTTP-01 challenge, or use a DNS-01 certbot plugin for your DNS provider to avoid the port.
2. Create the group and the root-owned certificate directory the deploy hook installs into. `service install` reuses an existing group. The relay's state directory is writable by the service, so it can't hold the certificate.

   ```bash
   sudo groupadd --system --force minip2p-relay
   sudo install -d -o root -g minip2p-relay -m 0750 /etc/minip2p-relay/tls
   ```

3. Install this deploy hook as `/usr/local/sbin/minip2p-relay-cert-hook` (owned by root, mode `0755`). It copies the renewed files under temporary names, then moves them into place, so the relay never reads a half-written file. The relay picks them up within about a minute, so the hook doesn't restart it:

   ```sh
   #!/bin/sh
   set -eu
   [ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/relay.example.com ] || exit 0
   dir=/etc/minip2p-relay/tls
   for file in fullchain.pem privkey.pem; do
     install -o root -g minip2p-relay -m 0640 "$RENEWED_LINEAGE/$file" "$dir/.$file.tmp"
     mv "$dir/.$file.tmp" "$dir/$file"
   done
   ```

4. Issue the certificate. Certbot runs the hook now and saves it for every renewal. This first issuance comes before `service install`, so the relay starts with the certificate and needs no restart either. Then confirm `/etc/minip2p-relay/tls/fullchain.pem` and `privkey.pem` exist.

   ```bash
   sudo certbot certonly --standalone -d relay.example.com --key-type ecdsa \
     --deploy-hook /usr/local/sbin/minip2p-relay-cert-hook
   ```

5. Install the service with the certificate. The unit adds `--webtransport` and announces `/dns/relay.example.com/udp/19876/quic-v1/webtransport`:

   ```bash
   sudo minip2p-relay service install --hostname relay.example.com \
     --webtransport-cert /etc/minip2p-relay/tls/fullchain.pem \
     --webtransport-key /etc/minip2p-relay/tls/privkey.pem
   ```

6. Check renewal end to end once: run `sudo certbot renew --cert-name relay.example.com --force-renewal`, then confirm within a minute that `minip2p-relay service logs` shows `[relay] webtransport certificate reloaded not_after=…` with the new date. The relay keeps running, with its reservations and circuits.

Use `service install --webtransport` without a certificate to serve browsers with the rotating self-signed certificates instead. The unit then announces no WebTransport address: an announced certhash would go stale within 26 days, and explicit announces replace listener addresses in reservation replies. Browsers must get the current `webtransport=` address from the logs.
