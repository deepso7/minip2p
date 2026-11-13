# Relay infrastructure

This directory holds the relay container image (`Dockerfile`, published as `ghcr.io/deepso7/minip2p-relay`) and the runbook for the project's public relay, `relay.minip2p.com`. Its user-facing addresses are on the docs site at [Public relay](../../docs/md/docs/reference/public-relay.mdx).

## `relay.minip2p.com`

- **Instance:** `i-06975a5524fb8024d` (`t3.micro`, Ubuntu, `ap-south-1c`). Log in as `ubuntu`.
- **DNS:** `A 13.200.143.202` and `AAAA 2406:da1a:515:6cb6:8928:6c77:ed2:2ebe`. The IPv4 address is the instance's auto-assigned public IP, not an Elastic IP: stopping and starting the instance changes it, and the `A` record must follow. A reboot keeps it.
- **Security groups:** `relay-server-sg` allows TCP and UDP `19876` (relay) and TCP `80` (certbot's HTTP-01 challenge).
- **Peer ID:** `12D3KooWNAHhp6rp11SvCDA84zua3hhEYTLNjgKmEDmt1BddtLdf`, from `/var/lib/minip2p-relay/identity.key`. Losing that file changes the peer ID and breaks every published address, so back it up before replacing the instance.
- **Service:** the systemd unit `minip2p-relay` from `minip2p-relay service install`, announcing `/dns/relay.minip2p.com/tcp/19876` and `/dns/relay.minip2p.com/udp/19876/quic-v1`, with WebTransport on a Let's Encrypt certificate.

### Operate it

```bash
minip2p-relay service status
minip2p-relay service logs
```

A healthy start logs the peer ID, TCP, QUIC, and WebTransport listeners on IPv4 and IPv6, then `webtransport=/dns/relay.minip2p.com/udp/19876/quic-v1/webtransport/p2p/…` and `webtransport_certificate_not_after=…`.

Upgrade to the latest release:

```bash
curl -fsSL https://minip2p.com/install/relay.sh | sh
sudo minip2p-relay service restart
```

### Certificate

Certbot owns the `relay.minip2p.com` lineage, issued with `--standalone --key-type ecdsa`. Its deploy hook, `/usr/local/sbin/minip2p-relay-cert-hook`, copies `fullchain.pem` and `privkey.pem` into `/etc/minip2p-relay/tls/` (root:minip2p-relay, 0640). The relay polls those files every 30 seconds and reloads them without a restart, logging `[relay] webtransport certificate reloaded not_after=…`. A rejected file (unreadable, mismatched key, expired) logs `[relay] webtransport certificate reload failed, still serving the previous one: …` instead. If neither line follows a renewal, the hook didn't run.

Certbot renews about 30 days before expiry. To test the whole path:

```bash
sudo certbot renew --cert-name relay.minip2p.com --force-renewal
minip2p-relay service logs   # expect a new "certificate reloaded" line with a later not_after within a minute
```

The full setup, including the hook's contents, is in the [WebTransport CA certificates plan](../../docs/plans/webtransport-ca-certificates.md#ops-relayminip2pcom) and [Stable browser addresses](../../docs/md/docs/rust/webtransport-certificates.mdx).
