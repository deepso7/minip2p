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
sudo openssl x509 -noout -enddate -in /etc/letsencrypt/live/relay.minip2p.com/fullchain.pem
minip2p-relay service logs
```

Within a minute, the logs should show a `certificate reloaded` line timestamped after the renewal, whose `not_after` matches the `notAfter` that `openssl` printed.

The full setup, including the hook's contents, is in the [WebTransport CA certificates plan](../../docs/plans/webtransport-ca-certificates.md#ops-relayminip2pcom) and [Stable browser addresses](../../docs/md/docs/rust/webtransport-certificates.mdx).

## Relay mesh runbook

Not carried out yet. These steps turn `relay.minip2p.com` into a relay mesh: several regions behind one address, with geo DNS sending each client to the nearest one ([plan](../../docs/plans/relay-mesh.md#ops-relayminip2pcom-as-a-mesh), [ADR 0027](../../docs/adr/0027-relay-mesh-two-identities-and-single-hop-forwarding.md)). Every node runs with the current `identity.key`, so the peer ID and every published address stay the same. Each node also has its own backbone key and links to the others on UDP `19877`.

### Regions

| Region | Role |
| --- | --- |
| `ap-south-1` (Mumbai) | the current instance; keeps its identity |
| `eu-central-1` (Frankfurt) | new |
| `us-east-1` | new |

Give every node an Elastic IP, Mumbai included: the current instance has an auto-assigned IPv4 address that changes on stop/start, and the member list and DNS records need fixed addresses. Attach Mumbai's before any DNS change, and update its `A` record to it. Keep NTP running on every node (Ubuntu's default `systemd-timesyncd` is enough): reservation expiries cross the backbone as UNIX seconds.

### Keys

- **Public identity.** Mumbai keeps `/var/lib/minip2p-relay/identity.key`. `service install` refuses to replace an existing identity, so Mumbai never imports one. Copy the key once into SSM Parameter Store as a SecureString, readable only by the relay instances' role. On Mumbai, with credentials allowed to write the parameter:

  ```bash
  sudo aws ssm put-parameter --region ap-south-1 --name /minip2p/relay/identity-key \
    --type SecureString --value file:///var/lib/minip2p-relay/identity.key
  ```

  Each new node fetches the key into a file only root can read, imports it on its first install (below), and deletes the copy:

  ```bash
  (umask 077; aws ssm get-parameter --region ap-south-1 --name /minip2p/relay/identity-key \
    --with-decryption --query Parameter.Value --output text > /root/identity.key)
  ```

- **Backbone keys.** Each node creates its own at `/var/lib/minip2p-relay/mesh.key` on its first start with `--mesh`, and prints its backbone address as `[relay] mesh listening=/ip4/0.0.0.0/udp/19877/quic-v1/p2p/<backbone peer ID>`. Put the node's Elastic IP in place of `0.0.0.0` to get its member entry, `/ip4/<elastic ip>/udp/19877/quic-v1/p2p/<backbone peer ID>`. The full list of entries is the member list, the same on every node.

A breach of any node exposes the public identity for the whole mesh, and replacing it changes every published address: no SSH open to the world, and nothing but the relay role can read the parameter.

### Security groups

Each node's group opens UDP `19877` only to the other members' Elastic IPs. The public ports (TCP and UDP `19876`) stay as they are. Once DNS-01 is in place (below), TCP `80` can close.

### DNS

`minip2p.com` stays on Cloudflare, whose geo steering needs the paid Load Balancing add-on. Instead, delegate `relay.minip2p.com` to Route 53:

1. Create a public hosted zone `relay.minip2p.com` in Route 53, and add its four name servers in Cloudflare as `NS` records for `relay`. Remove the old `A`/`AAAA` records for `relay` in Cloudflare in the same change, since a name can't have both `NS` and address records.
2. Before the delegation, recreate the current single `A` and `AAAA` records in the new zone, so the cutover itself changes nothing.
3. Create one Route 53 health check per node: TCP on the node's Elastic IP, port `19876`. Route 53 can't probe UDP, so TCP stands in for the node being up.
4. When the rollout reaches it, replace the single records with one latency-routed `A` record per region (the node's Elastic IP) and one `AAAA` per region (the node's IPv6 address), each with its region's set identifier and health check. Use plain records, not alias records, so each carries its health check directly ([how Route 53 chooses records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-how-route-53-chooses-records.html)). A dead node then drops out of DNS.

### Certificates

Behind geo DNS, Let's Encrypt's HTTP-01 check reaches whichever region its vantage points resolve to, so every node switches to DNS-01 through the Route 53 zone. Each node issues its own certificate:

```bash
sudo apt install python3-certbot-dns-route53
sudo certbot certonly --dns-route53 -d relay.minip2p.com --key-type ecdsa \
  --cert-name relay.minip2p.com \
  --deploy-hook /usr/local/sbin/minip2p-relay-cert-hook
```

The instance role needs `route53:ListHostedZones`, `route53:GetChange`, and `route53:ChangeResourceRecordSets` on the `relay.minip2p.com` zone only, limited to the challenge record with the condition `ForAllValues:StringEquals` `route53:ChangeResourceRecordSetsNormalizedRecordNames` = `_acme-challenge.relay.minip2p.com`. The deploy hook and live reload stay as in [Certificate](#certificate); set up the hook and `/etc/minip2p-relay/tls` on each new node as described there. Three nodes stay under Let's Encrypt's limit of 5 duplicate certificates per week, but the forced-renewal test counts against it, so test one node at a time.

### Rollout

1. **Mumbai alone.** Upgrade it to the mesh release and reinstall its service with a backbone key and no members. It behaves as today:

   ```bash
   sudo minip2p-relay service install --hostname relay.minip2p.com \
     --webtransport-cert /etc/minip2p-relay/tls/fullchain.pem \
     --webtransport-key /etc/minip2p-relay/tls/privkey.pem \
     --mesh
   minip2p-relay service logs
   ```

   Note its `mesh listening=` line and build its member entry.
2. **New regions.** On each new node: attach its Elastic IP, install the relay, fetch the identity key from SSM, and set up its certificate. Then install with the imported identity and a backbone key, still without members:

   ```bash
   sudo minip2p-relay service install --hostname relay.minip2p.com \
     --import-key /root/identity.key \
     --webtransport-cert /etc/minip2p-relay/tls/fullchain.pem \
     --webtransport-key /etc/minip2p-relay/tls/privkey.pem \
     --mesh
   sudo rm /root/identity.key
   ```

   Check that its `[relay] peer=` line shows `12D3KooWNAHhp6rp11SvCDA84zua3hhEYTLNjgKmEDmt1BddtLdf`, and build its member entry from its `mesh listening=` line.
3. **Member list.** With every node's entry known, rerun `service install` on every node, Mumbai included, with the same flags as before minus `--import-key`, plus the full list. Every node takes the same list and skips its own entry:

   ```bash
   sudo minip2p-relay service install --hostname relay.minip2p.com \
     --webtransport-cert /etc/minip2p-relay/tls/fullchain.pem \
     --webtransport-key /etc/minip2p-relay/tls/privkey.pem \
     --mesh-member /ip4/<mumbai eip>/udp/19877/quic-v1/p2p/<mumbai backbone id> \
     --mesh-member /ip4/<frankfurt eip>/udp/19877/quic-v1/p2p/<frankfurt backbone id> \
     --mesh-member /ip4/<us eip>/udp/19877/quic-v1/p2p/<us backbone id>
   ```

   A node closes backbone connections from peers not on its list, so links come up once both ends have it.
4. **Check the links,** then **switch DNS.** Every node's logs should show `[relay] mesh member=<id> up` for every other member. Then replace the single records with the latency records (DNS step 4).
5. **Verify live.** From a client in each region, connect to a peer reserved from another region through `relay.minip2p.com`. The entry node logs `circuit opened … via=<holding node's backbone id>`.

`[relay] mesh member=<id> down` means a backbone link dropped; the node redials it with backoff. Health checks can't see a backbone partition, so alert on that line. While a link is down, the two nodes answer `NO_RESERVATION` for each other's peers.
