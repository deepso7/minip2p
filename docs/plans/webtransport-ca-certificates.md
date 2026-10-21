# Plan: CA-signed WebTransport certificates

> **Status:** Implemented on branch feat/webtransport-ca-certs. Review history: draft reviewed with gpt-6.1-sol (high). Round 1: 9 findings (1 high). Round 2: "ready with changes" (3 findings, 2 of them round-1 fixes judged insufficient). Every finding was checked against the code and fixed. The round-2 fixes were not re-reviewed.

## Goal

A WebTransport listener that has a domain and a CA-signed certificate, such as `relay.minip2p.com` with Let's Encrypt, serves that certificate to browsers. Browsers dial a permanent address with no `/certhash`:

```
/dns/relay.minip2p.com/udp/19876/quic-v1/webtransport/p2p/12D3KooW…
```

The browser checks the certificate chain the way it checks any HTTPS page, and Noise authenticates the peer ID as before. This is the libp2p spec's first verification path ([webtransport spec, Certificates](https://github.com/libp2p/specs/blob/master/webtransport/README.md#certificates)): "libp2p nodes that possess a CA-signed TLS certificate MAY use that certificate … [and] SHOULD NOT add a `/certhash` component".

Why: self-signed certificates rotate every 13 days (`crates/tls/src/webtransport.rs`), so any address with a certhash that is hardcoded or announced goes stale within about 26 days. A relay we host needs one address that never changes.

Non-goals:

- **No ACME client in minip2p.** Certificates come from files the operator manages (certbot or similar).
- **No file watching in minip2p.** The transport and Endpoint replace the certificate on request (Decision 9); noticing a renewed file is the host's job.
- **No mixed mode on one transport.** A transport presents either the derived rotating certificate or the provided one, never both (Decision 2).
- **No native WebTransport dialer.** That's unchanged from ADR 0023.
- **No change to `quic-v1`.** libp2p peers still get the libp2p certificate by ALPN.

## Decisions

### 1. The address shape already exists

`Multiaddr::is_webtransport()` accepts zero or more `/certhash` components (`crates/core/src/multiaddr.rs:276`), and `webtransport_url` already turns `/dns*` hosts into `https://<name>:<port>/.well-known/libp2p-webtransport?type=noise`. No new address shape is needed.

### 2. One certificate source per transport

The QUIC transport gets a `WebTransportCertificates` choice in its config:

```rust
pub enum WebTransportCertificates {
    /// Today's behaviour: per-period certificates derived from the identity key, rotated by the host clock.
    Derived,
    /// A CA-signed chain and its private key (DER), presented to every h3 client.
    Provided { chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static> },
}
```

`Derived` is the default. With `Provided`:

- `Rotation` is not created. A small enum replaces `Option<Rotation>` in the transport (`transports/quic/src/lib.rs:372`), so `rotate()` becomes a no-op and the rotation deadline disappears from `poll`'s timer.
- The `AlpnResolver` cell (`WebTransportCertificate`, `tls.rs:238`) holds the provided `CertifiedKey`. Clients offering `libp2p` still get the libp2p certificate.
- `local_addresses_revision` stays at 0 forever, there is no rotation deadline, and nothing triggers re-announcing `Listening`.
- At bind time, rustls's `CertifiedKey::keys_match` checks that the key matches the leaf. A leaf whose validity window has already passed, according to the host clock, is a bind error, not a silent failure in the browser. A not-yet-valid or soon-to-expire leaf is accepted (an operator fixing clocks mid-renewal shouldn't be blocked); the relay logs its `notAfter` (Risks covers expiry monitoring).
- RSA keys are allowed. The W3C ban on RSA applies only to hash-pinned certificates.

Rejected: picking the certificate by SNI so that one socket serves both certhash and CA modes. It works (a certhash dial to an IP sends no SNI, while a `/dns` dial sends the name), but no current user needs both, and it doubles the Listening-address and Noise-list logic. It's the natural extension if one appears.

### 3. Noise lists the leaf's hash

The spec says the server "MUST include the certificate hash of the currently used certificate" in `webtransport_certhashes`. In `Provided` mode, `WebTransportContext.certhashes` is `[sha256(leaf DER)]`. A browser that dialed without a certhash has nothing to check, so the list can't fail it. The server always sends the extension, because the spec requires it. That isn't needed for our own client: `client.rs:633` treats missing extensions as an empty list, which passes when the dialed list is empty too.

Pinning a CA leaf by hash is a different matter. `serverCertificateHashes` imposes the W3C limits of at most 14 days' validity and no RSA, whoever issued the certificate. An ordinary 90-day Let's Encrypt leaf therefore can't be dialed with its certhash, and CA-mode addresses must be hash-free. The relay never prints a certhash address in this mode.

### 4. Listening addresses carry no certhash

In `Provided` mode, `socket_addresses` reports `/<ip>/udp/<port>/quic-v1/webtransport` with no certhash: the true shape per the spec. A browser that learns that IP address through Identify fails WebPKI, because the certificate names the domain and not the IP. That's harmless (the dial fails cleanly), and it matches what other libp2p implementations do. The address browsers should use is the operator's `/dns/…/webtransport` announce (Decision 6).

### 5. Endpoint API

```rust
Endpoint::builder()
    .listen_on("/ip4/0.0.0.0/udp/19876/quic-v1/webtransport")?
    .webtransport_certificate_pem(&chain_pem, &key_pem)?   // parses now, validated at bind
    .bind()?;
```

- PEM is parsed with `rustls-pki-types`'s `PemObject` (already in the dependency tree via rustls). Parse errors (no certificate, no key, or more than one key) are `EndpointOptionsError`s that name the problem.
- Without a WebTransport listen address, the option is an error. Silently ignoring it would hide a typo'd listen address.
- `ffi-core`, UniFFI, and the web shell don't get the option in v1. Native apps on phones or in browsers don't host CA-certified listeners. Add it when someone asks.

### 6. Relay server

- CLI: `--webtransport-cert PATH --webtransport-key PATH`. Both are required together, and either one implies `--webtransport`. The files are read before binding, and errors name the path.
- `crates/relay-server/src/address.rs` rejects WebTransport announces without a certhash ("No browser can dial a WebTransport address without a certhash", line 230). That's no longer true. The check moves up: `relay_server_announce_addrs` accepts a certhash-free WebTransport announce only when the builder has a provided certificate. Without one, the error says to add the certhash or configure a CA certificate. This keeps the safety check for self-signed relays.
- The rule works both ways. In derived mode a WebTransport announce must carry a certhash. In provided mode it must not, because a hash makes the browser pin instead of checking the chain, and a long-lived CA leaf fails pinning (Decision 3). Each error says which mode the endpoint is in and what to change.
- `Endpoint` remembers the certificate mode, and `set_relay_server_announce_addrs` (`crates/minip2p/src/std/mod.rs:999`) applies the same rule at runtime. On rejection, the previous override stays active, as it does today.
- On startup the relay prints `[relay] webtransport=/dns/…` for each announced WebTransport address, and the leaf's `notAfter`.
- `service install` gets `--webtransport` and `--webtransport-cert/--webtransport-key` passthrough. When a certificate is given, the unit announces `/dns/{hostname}/udp/19876/quic-v1/webtransport`, so `systemctl edit` isn't needed.

### 7. Browser client

- `WebTransportClient::dial` (`transports/webtransport/src/client.rs:915`) stops rejecting addresses with no certhash. With an empty list it dials with WebPKI.
- `bindings/ts/web/src/io.ts` leaves out `serverCertificateHashes` when the list is empty (passing an empty array works per spec, but omitting it is what every working CA example does and avoids engine quirks).
- `dns` names go to the browser untouched. The web shell does no DNS resolution of its own, so WebPKI sees the real hostname. This needs a test.
- Doc comments that say "dials `…/webtransport/certhash/…` addresses" are updated.

### 8. Docs

- `GLOSSARY.md`: **Certhash** gets "(self-signed mode only)". A new entry, **CA certificate mode**, covers a WebTransport listener that presents an operator-supplied CA-signed certificate, carries no certhash, and doesn't rotate.
- ADR 0024 records Decisions 2 to 4. ADR 0023's "CA mode is a non-goal" note gets a "superseded in part by 0024" link, and `docs/plans/webtransport.md`'s non-goal line links here.
- Package READMEs, each updated in the PR that changes it:
  - `bindings/ts/web/README.md:42` ("There is no CA-certificate mode") and `crates/web/README.md`, in PR 1;
  - `transports/webtransport/README.md:64` (hash-free dials are `Unsupported`), in PR 1;
  - `transports/quic/README.md` (addresses at line 21, the certificate choice at line 148, and "Certificate rotation" gets a provided-mode note), in PR 2;
  - `crates/minip2p/README.md:26` (the rotation and `ListenAddressesChanged` paragraph applies to derived mode only), in PR 3.
- The relay README gets a "Browsers with a stable address" section with the certbot recipe below. It also fixes the "stays the same across restarts" line to mention the 13-day rotation.

### 9. Live reload

A renewal needs no restart, so reservations and circuits survive it.

- `QuicTransport::replace_webtransport_certificate(chain, key)` runs bind's checks (key matches leaf, leaf not expired by the host clock) through the same code, then swaps both the resolver cell and the Noise context (the new leaf's hash). New handshakes get the new certificate; live connections keep theirs. Hash-free addresses don't change: no `Listening` event, revision unchanged. On error nothing changes. A transport in derived mode, or without a WebTransport listener, returns `WebTransportCertificateError::NotProvided`.
- The Endpoint boxes its transports in a `TransportSet`, so it can't reach `QuicTransport`. At bind it keeps the transport's `WebTransportCertificateHandle` (`Some` only in provided mode), which shares both cells. `Endpoint::set_webtransport_certificate_pem(chain_pem, key_pem)` parses with the builder's PEM code and replaces through it, on the caller's thread: no driver command is needed, since the cells are what the transport reads on its next handshake. Errors: `SetWebTransportCertificateError::{NotConfigured, Pem, Invalid}`.
- The relay checks both files' modification times every 30 seconds (`--webtransport-reload-secs`) and, when either changed, reloads both and calls it, logging `[relay] webtransport certificate reloaded not_after=…`. A failed load (unreadable, mismatched key, expired) logs one stderr line and keeps the old certificate; it is retried only when a file changes again, so the deploy hook's second rename (the key) retries a load that caught the chain alone.

## Ops: `relay.minip2p.com`

Certificates live in a root-controlled tree, so a compromised relay can't swap in symlinks for a root process to follow. The relay's own state directory, `/var/lib/minip2p-relay`, is writable by the service, so it can't hold them.

1. Open TCP 80 in the security group for the HTTP-01 challenge (or use DNS-01 if the DNS provider has a certbot plugin, which avoids the port).
2. Create what the hook needs before the first issuance: `sudo groupadd --system minip2p-relay` (`service install` reuses an existing group, `service.rs:132`) and `sudo install -d -o root -g minip2p-relay -m 0750 /etc/minip2p-relay/tls`.
3. Install the deploy hook `/usr/local/sbin/minip2p-relay-cert-hook` (root, 0755). It exits unless `$RENEWED_LINEAGE` is `/etc/letsencrypt/live/relay.minip2p.com`. For each of `fullchain.pem` and `privkey.pem`, it runs `install -o root -g minip2p-relay -m 0640` into a temporary name in `/etc/minip2p-relay/tls/` (root:minip2p-relay, 0750), then `mv` onto the final name, so the relay never reads a half-written file. It doesn't restart the relay: the relay picks up the renewed files within about a minute without dropping reservations or circuits (Decision 9).
4. `sudo certbot certonly --standalone -d relay.minip2p.com --key-type ecdsa --deploy-hook /usr/local/sbin/minip2p-relay-cert-hook`. Certbot runs the hook for this first issuance and saves it in the lineage's renewal config, so every renewal runs it too. This first issuance comes before `service install`, so the relay starts with the certificate and needs no restart either. Then confirm both `/etc/minip2p-relay/tls/fullchain.pem` and `privkey.pem` exist before going on.
5. `minip2p-relay service install --hostname relay.minip2p.com --webtransport-cert /etc/minip2p-relay/tls/fullchain.pem --webtransport-key /etc/minip2p-relay/tls/privkey.pem`. `ProtectSystem=strict` leaves `/etc` readable, and the service user gets read access through the group.
6. Check renewal end to end: run `sudo certbot renew --cert-name relay.minip2p.com --force-renewal` once, then confirm within a minute that the relay logs `[relay] webtransport certificate reloaded not_after=…` with the new date.
7. Hardcode `/dns/relay.minip2p.com/udp/19876/quic-v1/webtransport/p2p/12D3KooWNAHh…` in the web app.

## PR stack

1. **`webtransport, web: dial without a certhash`.** Client change (`client.rs:915`), TS `io.ts` change, and their unit tests. It lands first, so PR 2 can test end to end.
2. **`quic: CA-signed WebTransport certificates`.** `WebTransportCertificates`, the resolver and Noise context in `Provided` mode, Listening addresses, and bind validation.
   - **Fixtures:** static PEM files in `transports/quic/tests/fixtures/ca/`: a CA root (`basicConstraints CA:TRUE`), a `localhost` leaf it signed (SAN `DNS:localhost`, `CA:FALSE`, valid until 2125), and an expired leaf. A `README` in that directory has the `openssl` commands that made them. Static files keep test-only CA profiles out of `minip2p-tls`'s production generator, whose profile is fixed to self-signed (`generate.rs:203`), and avoid a dev-dependency.
   - **Harness:** the test `WebTransportIo` (`transports/quic/tests/common/wt_client.rs:728`) takes an optional root store and server name, instead of always using the socket IP with hash pinning.
3. **`minip2p: webtransport_certificate_pem`.** Builder option, PEM parsing errors, and announce validation for both the builder and `set_relay_server_announce_addrs`.
4. **`relay-server: --webtransport-cert/--webtransport-key`.** CLI, `service install` passthrough, the expiry warning, README (including the ops recipe), glossary, and ADR 0024.

Each PR depends on the one before it.

## Testing

- Native end to end (PR 2): the test client trusts the fixture root, dials `/ip4/127.0.0.1/udp/<p>/quic-v1/webtransport` with server name `localhost`, and completes Noise. On a dual socket, a `libp2p` dial still gets the libp2p certificate.
- Negative cases (PR 2): an untrusted root fails TLS; server name `example.com` fails TLS; the expired leaf fails at bind; a key that doesn't match the leaf fails at bind.
- Provided-mode invariants (PR 2), in one test: with the host clock set just before a period boundary, then moved past it, then jumped by a year, the Listening addresses and `local_addresses_revision` don't change, `poll`'s deadline has no rotation component, no `Listening` event is emitted, and re-listening reports the hash-free address.
- Announce policy (PR 3), in the builder and at runtime: derived mode rejects a hash-free WebTransport announce, provided mode accepts it and rejects one with a certhash. A runtime rejection keeps the previous override.
- Browser (manual, not CI): Chrome and Firefox dial `relay.minip2p.com` after the deploy. Getting Playwright to trust a test CA is possible (`--ignore-certificate-errors-spki-list`), but it tests the flag rather than WebPKI. Skip it.
- Fuzz: no new wire decoder.

## Follow-ups

- SNI-based mixed mode (Decision 2, rejected for now).
- FFI and web config surface for the option.

## Risks

| Risk | Mitigation |
| --- | --- |
| The relay restarts on renewal and drops every reservation | It doesn't: the relay notices the renewed files and swaps the certificate in place (Decision 9). New handshakes get the new certificate; live connections, reservations, and circuits keep running. |
| The certificate expires because renewal or the deploy hook broke | Let's Encrypt no longer sends expiry emails (ended 2025-06-04). A working renewal reloads a fresh certificate, so the relay itself checks: at startup, after each reload, and then daily (driven by its own loop's clock), it logs a `warning` when the leaf it serves has less than 14 days left. Point log alerting, or a cron `journalctl` grep, at that line. |
| A browser quirk with WebPKI over WebTransport on a non-443 port | Chrome and Firefox allow any port. Verified by hand in the manual check. |
