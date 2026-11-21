//! The std [`EndpointBuilder`]: listen-address validation, transport binding, and
//! assembling the std [`Endpoint`] around the bound [`TransportSet`].

use super::*;
#[cfg(feature = "relay")]
use crate::CircuitLimits;
#[cfg(feature = "mdns")]
use crate::MdnsConfig;
#[cfg(all(feature = "relay-server", feature = "quic"))]
use crate::RelayMeshConfig;
use crate::builder::{CommonBuilder, EndpointBuilder};
#[cfg(feature = "relay")]
use crate::nat::CircuitOps;
use crate::setup::{self, Capabilities};
#[cfg(feature = "relay-server")]
use crate::{RelayServerAddressError, RelayServerAddressErrorKind, RelayServerConfig};
use minip2p_core::Multiaddr;
#[cfg(any(feature = "quic", feature = "tcp", feature = "relay-server"))]
use minip2p_core::Protocol;
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_core::TransportKind;
use minip2p_core::platform::{StdClock, StdEntropy};
#[cfg(feature = "quic")]
use minip2p_quic::{QuicNodeConfig, QuicTransport, WebTransportCertificates};
#[cfg(all(feature = "relay-server", feature = "quic"))]
use minip2p_swarm::{SwarmBuilder, SwarmTimeouts};
#[cfg(feature = "tcp")]
use minip2p_tcp::{StdTcpProvider, TcpConfig, TcpTransport};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
use minip2p_transport::SharedPoll;
#[cfg(feature = "tcp")]
use minip2p_transport::Transport;
#[cfg(any(feature = "quic", feature = "tcp"))]
use std::str::FromStr;

/// Default dual-stack QUIC listen addresses used by
/// [`EndpointBuilder::listen_default`].
#[cfg(feature = "quic")]
pub(super) fn default_listen_quic_addrs() -> [Multiaddr; 2] {
    [
        Multiaddr::from_protocols(vec![
            Protocol::Ip4([0, 0, 0, 0]),
            Protocol::Udp(0),
            Protocol::QuicV1,
        ]),
        Multiaddr::from_protocols(vec![
            Protocol::Ip6([0; 16]),
            Protocol::Udp(0),
            Protocol::QuicV1,
        ]),
    ]
}

/// What the std [`EndpointBuilder`] adds to the shared options: identity,
/// transport limits and certificates, listen addresses, and the relay
/// server's announce addresses and mesh.
pub struct StdBuilderState {
    keypair: Option<Ed25519Keypair>,
    #[cfg(feature = "quic")]
    quic_limits: QuicLimits,
    /// What WebTransport listeners present to browsers.
    #[cfg(feature = "quic")]
    webtransport_certificates: WebTransportCertificates,
    #[cfg(feature = "tcp")]
    tcp_config: TcpConfig,
    /// Ordered listen addresses; transport is inferred from address shape.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    listen_addrs: Vec<Multiaddr>,
    #[cfg(feature = "relay-server")]
    relay_server_announce_addrs: Vec<Multiaddr>,
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    relay_mesh: Option<RelayMeshConfig>,
    #[cfg(feature = "relay")]
    circuit_limits: CircuitLimits,
}

#[cfg_attr(
    not(feature = "tcp"),
    expect(
        clippy::derivable_impls,
        reason = "With `tcp`, the TCP config starts from `TcpConfig::std_default`, not `Default`."
    )
)]
impl Default for StdBuilderState {
    fn default() -> Self {
        Self {
            keypair: None,
            #[cfg(feature = "quic")]
            quic_limits: QuicLimits::default(),
            #[cfg(feature = "quic")]
            webtransport_certificates: WebTransportCertificates::default(),
            #[cfg(feature = "tcp")]
            tcp_config: TcpConfig::std_default(),
            #[cfg(any(feature = "quic", feature = "tcp"))]
            listen_addrs: Vec::new(),
            #[cfg(feature = "relay-server")]
            relay_server_announce_addrs: Vec::new(),
            #[cfg(all(feature = "relay-server", feature = "quic"))]
            relay_mesh: None,
            #[cfg(feature = "relay")]
            circuit_limits: CircuitLimits::default(),
        }
    }
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            common: CommonBuilder::default(),
            state: StdBuilderState::default(),
        }
    }
}

impl EndpointBuilder<StdBuilderState> {
    /// Uses an explicit host keypair.
    pub fn identity(mut self, keypair: Ed25519Keypair) -> Self {
        self.state.keypair = Some(keypair);
        self
    }

    /// Overrides QUIC connection, stream, queue, window and timeout limits.
    /// The windows default to quinn's own (ADR 0022).
    #[cfg(feature = "quic")]
    pub fn quic_limits(mut self, limits: QuicLimits) -> Self {
        self.state.quic_limits = limits;
        self
    }

    /// Serves WebTransport with a CA-signed certificate instead of the
    /// rotating self-signed ones derived from the identity key.
    ///
    /// `chain_pem` holds the leaf certificate first, then its intermediates
    /// (certbot's `fullchain.pem`); `key_pem` holds the leaf's one private
    /// key (`privkey.pem`, PKCS#8, SEC1 or PKCS#1). Both are parsed here, so a
    /// missing certificate or key, or a second key, is an
    /// [`EndpointOptionsError::WebTransportCertificatePem`].
    /// [`bind`](Self::bind) then checks that the key matches the leaf and the
    /// leaf has not expired ([`BindError::Quic`]), and that a
    /// `/quic-v1/webtransport` listen address exists to serve it
    /// ([`EndpointOptionsError::WebTransportCertificateWithoutListener`]).
    ///
    /// Browsers check the certificate the way they check any HTTPS page, so
    /// they must dial the domain it names, with no `/certhash`:
    /// `/dns/relay.example.com/udp/<port>/quic-v1/webtransport/p2p/…`. The
    /// certificate never rotates, so the listen addresses carry no
    /// `/certhash` and never change. Replace it after a renewal, without a
    /// restart, with [`Endpoint::set_webtransport_certificate_pem`].
    #[cfg(feature = "quic")]
    pub fn webtransport_certificate_pem(
        mut self,
        chain_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<Self, EndpointOptionsError> {
        let (chain, key) = parse_certificate_pem(chain_pem.as_ref(), key_pem.as_ref())
            .map_err(|problem| EndpointOptionsError::WebTransportCertificatePem { problem })?;
        self.state.webtransport_certificates = WebTransportCertificates::Provided { chain, key };
        Ok(self)
    }

    /// Overrides TCP connection, buffer, timeout and Yamux limits, and the
    /// connection-id namespace the TCP transport allocates in. Checked at bind
    /// ([`EndpointOptionsError::InvalidLimit`]).
    ///
    /// Without this the endpoint binds with [`TcpConfig::std_default`], whose
    /// 1,664 KiB Yamux receive window keeps a 100 Mbit/s, 100 ms path busy
    /// (ADR 0120). Start overrides from it: [`TcpConfig::default`] is the
    /// portable profile, with the specification's 256 KiB window.
    ///
    /// [`TcpConfig::handshake_timeout_ms`] (30 s) caps the Noise + Yamux
    /// upgrade on its own, so a slow link needs it raised alongside the
    /// connect and swarm deadlines. Size each from how long that exchange
    /// takes on the loaded link, plus slack for at least one retransmission;
    /// no fixed multiple of the RTT is enough, and no deadline keeps a link
    /// usable while a bulk transfer keeps its queue full (shape or pause the
    /// bulk traffic instead). The values below are placeholders for your own
    /// measurements, as in the `minip2p-rs` README's Deadlines section:
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use minip2p::{Endpoint, SwarmTimeouts, TcpConfig};
    ///
    /// let endpoint = Endpoint::builder()
    ///     .listen_on("/ip4/0.0.0.0/tcp/0")?
    ///     .timeouts(SwarmTimeouts {
    ///         negotiation_ms: 30_000, // the default: an ordinary outbound stream's negotiation
    ///         identify_ms: 60_000,    // the first Identify: open, negotiation and reply
    ///         ping_ms: 30_000,        // one ping: open, negotiation and echo
    ///     })
    ///     .tcp_config(TcpConfig {
    ///         handshake_timeout_ms: Some(60_000), // the Noise + Yamux upgrade
    ///         ..TcpConfig::std_default()
    ///     })
    ///     .connect_deadline(Duration::from_secs(90)) // dials plus their handshake
    ///     .bind()?;
    /// # drop(endpoint);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(feature = "tcp")]
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.state.tcp_config = config;
        self
    }

    /// Overrides the relay circuits' Yamux limits. Checked at bind
    /// ([`EndpointOptionsError::InvalidLimit`]).
    #[cfg(feature = "relay")]
    pub fn circuit_limits(mut self, limits: CircuitLimits) -> Self {
        self.state.circuit_limits = limits;
        self
    }

    /// Adds a listener from a complete transport multiaddress.
    ///
    /// QUIC (`/ip4|ip6/udp/<port>/quic-v1`), WebTransport
    /// (`/ip4|ip6/udp/<port>/quic-v1/webtransport`, without a `/certhash`:
    /// the node's certificate supplies it) and TCP (`/ip4|ip6/tcp/<port>`)
    /// shapes are accepted. A `quic-v1` and a WebTransport address on the
    /// same host and port share one UDP socket, which serves both.
    /// Compatible addresses are grouped at [`EndpointBuilder::bind`];
    /// unsupported or contradictory shapes fail here with an actionable
    /// error.
    ///
    /// Named `listen_on` to avoid colliding with [`Endpoint::listen`], which
    /// returns the first bound address after bind.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on(mut self, address: impl AsRef<str>) -> Result<Self, EndpointOptionsError> {
        let raw = address.as_ref();
        let parsed = Multiaddr::from_str(raw).map_err(|error| {
            EndpointOptionsError::InvalidListenAddress {
                addr: raw.to_string(),
                error,
            }
        })?;
        self.push_listen_addr(parsed)?;
        Ok(self)
    }

    /// Adds a listener from an already-parsed transport multiaddress.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on_multiaddr(
        mut self,
        address: &Multiaddr,
    ) -> Result<Self, EndpointOptionsError> {
        self.push_listen_addr(address.clone())?;
        Ok(self)
    }

    /// Configures the common dual-stack QUIC defaults
    /// (`/ip4/0.0.0.0/udp/0/quic-v1` and `/ip6/::/udp/0/quic-v1`).
    ///
    /// Returns [`EndpointOptionsError::DuplicateQuicFamily`] if the builder
    /// already has a QUIC listen for either family (same rule as
    /// [`Self::listen_on`]).
    #[cfg(feature = "quic")]
    pub fn listen_default(mut self) -> Result<Self, EndpointOptionsError> {
        for address in default_listen_quic_addrs() {
            self.push_listen_addr(address)?;
        }
        Ok(self)
    }

    #[cfg(any(feature = "quic", feature = "tcp"))]
    fn push_listen_addr(&mut self, address: Multiaddr) -> Result<(), EndpointOptionsError> {
        validate_listen_multiaddr(&address)?;
        #[cfg(feature = "quic")]
        if is_quic_listen(&address) {
            reject_duplicate_quic_family(&self.state.listen_addrs, &address)?;
        }
        self.state.listen_addrs.push(address);
        Ok(())
    }

    /// Configures advertised direct addresses without enabling relay service.
    ///
    /// This method validates direct TCP/QUIC/WebTransport shape, rejects wildcard
    /// and circuit addresses, and checks a trailing peer id against an
    /// already-fixed builder identity. Whether a WebTransport address must carry
    /// a `/certhash` depends on
    /// `EndpointBuilder::webtransport_certificate_pem`, so that is checked at
    /// bind: with the derived self-signed certificates it must, with a CA-signed
    /// one it must not. [`RelayServerAnnounceError`] preserves either the rejected input
    /// or a validator configuration failure. When identity is not fixed yet, the peer-id match is
    /// checked again at bind. Announce addresses alone do not enable the service;
    /// also call [`EndpointBuilder::relay_server`] or
    /// [`EndpointBuilder::relay_server_config`].
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected announce address for actionable host diagnostics."
    )]
    pub fn relay_server_announce_addrs(
        mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<Self, RelayServerAnnounceError> {
        let validation_peer = self
            .state
            .keypair
            .as_ref()
            .map(Ed25519Keypair::peer_id)
            .or_else(|| {
                addrs
                    .iter()
                    .find_map(|address| match address.iter().last() {
                        Some(Protocol::P2p(peer_id)) => Some(*peer_id),
                        _ => None,
                    })
            })
            .unwrap_or_else(|| Ed25519Keypair::generate().peer_id());
        let mut validator = minip2p_relay_server::RelayServerAgent::new(
            validation_peer,
            RelayServerConfig::default(),
        )?;
        validator.replace_announce_addrs(addrs.clone())?;
        self.state.relay_server_announce_addrs = addrs;
        Ok(self)
    }

    /// Makes this relay one node of a relay mesh: several relays that share
    /// this endpoint's identity, each serving the peers reserved on any of
    /// them by forwarding circuits over a backbone (see
    /// [`minip2p_relay_server::mesh`]).
    ///
    /// The backbone is a second swarm under
    /// [`RelayMeshConfig::identity`], over its own QUIC transport bound to
    /// [`RelayMeshConfig::listen`]. It shares this endpoint's wait, and its
    /// traffic never reaches the application: [`Endpoint::wait`] reports
    /// members joining and leaving, and peers refused, as
    /// [`EndpointEvent::RelayServer`] with
    /// [`RelayServerEvent::MeshMemberUp`](minip2p_relay_server::RelayServerEvent::MeshMemberUp),
    /// [`MeshMemberDown`](minip2p_relay_server::RelayServerEvent::MeshMemberDown)
    /// and
    /// [`MeshPeerRejected`](minip2p_relay_server::RelayServerEvent::MeshPeerRejected).
    ///
    /// There is no allowlist: a backbone peer is a member once it proves
    /// that this endpoint's identity signed its backbone peer id (ADR 0028),
    /// so every node must run under the same identity. Each node dials the
    /// members in [`RelayMeshConfig::members`] from the first drive, and
    /// redials them with backoff (1 s doubling to 30 s) while their link is
    /// down, and accepts any member that dials it. A link forms when either
    /// side lists the other, so a new node that lists every existing node
    /// joins the mesh without a change on the others. Nodes need synced
    /// clocks: reservation expiries cross the backbone as UNIX seconds.
    ///
    /// Needs [`relay_server`](Self::relay_server) or
    /// [`relay_server_config`](Self::relay_server_config), and replaces that
    /// config's [`mesh`](RelayServerConfig::mesh) with one signed for this
    /// node's backbone identity, keeping its directory limit.
    /// Checked at bind ([`BindError::Options`]): the backbone identity must
    /// differ from the endpoint's, and every listen and member address must
    /// be `/ip4|ip6/<ip>/udp/<port>/quic-v1`. A backbone socket that cannot
    /// be bound is [`BindError::RelayMesh`].
    ///
    /// ```no_run
    /// use minip2p::{Ed25519Keypair, Endpoint, PeerAddr, RelayMeshConfig};
    ///
    /// # let (public_key, backbone_key) = (Ed25519Keypair::generate(), Ed25519Keypair::generate());
    /// // The existing nodes' backbone addresses and backbone peer ids; a node skips its own.
    /// let members: Vec<PeerAddr> = vec![
    ///     "/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".parse()?,
    /// ];
    /// let endpoint = Endpoint::builder()
    ///     .identity(public_key) // the same on every node
    ///     .relay_server()
    ///     .relay_mesh(RelayMeshConfig::new(backbone_key, members))
    ///     .listen_on("/ip4/0.0.0.0/udp/19876/quic-v1")?
    ///     .bind()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    pub fn relay_mesh(mut self, config: RelayMeshConfig) -> Self {
        self.state.relay_mesh = Some(config);
        self
    }

    /// Enables local-link mDNS discovery with interoperable defaults.
    #[cfg(feature = "mdns")]
    pub fn mdns(mut self) -> Self {
        self.common.capabilities.mdns = Some(MdnsConfig::default());
        self
    }

    /// Enables local-link mDNS discovery with an explicit configuration,
    /// checked at bind before the QUIC or mDNS sockets open
    /// ([`BindError::Mdns`]).
    #[cfg(feature = "mdns")]
    pub fn mdns_config(mut self, config: MdnsConfig) -> Self {
        self.common.capabilities.mdns = Some(config);
        self
    }

    /// Builds the endpoint, bringing up every transport it was given.
    ///
    /// A `/udp/…/quic-v1` address is then dialed over QUIC and a `/tcp` one
    /// over TCP, decided from the address rather than by the caller. An
    /// endpoint with nothing to bind is refused: it could neither dial nor be
    /// reached, and failing here says so more clearly than every later call
    /// would.
    ///
    /// Every transport starts accepting at once, QUIC and TCP alike, so the
    /// returned endpoint is reachable on each listen address without a
    /// further call. [`Endpoint::listen_all`] reports those addresses.
    ///
    /// Every failure is a [`BindError`] naming what failed, before any event
    /// is polled; see its variants.
    pub fn bind(mut self) -> Result<Endpoint, BindError> {
        let (keypair, capabilities) = self.prepare()?;
        let (transport, _certificate) = bind_transports(&self, &keypair)?;
        let mut endpoint = build_endpoint(self, keypair, transport, capabilities)?;
        #[cfg(feature = "quic")]
        {
            endpoint.platform.webtransport_certificate = _certificate;
        }
        endpoint
            .engine
            .core
            .listen_on_bound_addrs()
            .map_err(|error| match error {
                Error::Transport(error) => BindError::Listen(error),
                _ => BindError::Invariant {
                    reason: "listening on bound addresses failed outside the transport",
                },
            })?;
        Ok(endpoint)
    }

    /// Validates the static configuration.
    ///
    /// Zero deadlines and reserved protocol ids are rejected here -- before any socket is
    /// bound -- so a configuration error can neither allocate resources
    /// nor be masked by a bind failure. Capabilities are validated by
    /// Endpoint setup, also before binding.
    fn validate(&self) -> Result<(), BindError> {
        self.common.timeouts.validate()?;
        #[cfg(feature = "quic")]
        if !self.common.inbound_limits.is_empty()
            && (self.state.listen_addrs.is_empty()
                || self.state.listen_addrs.iter().any(is_quic_listen))
            && !self
                .state
                .quic_limits
                .connection_receive_window_is_unlimited()
        {
            return Err(EndpointOptionsError::InboundLimitWithFiniteQuicWindow.into());
        }
        if let Some(protocol) = self
            .common
            .protocols()
            .iter()
            .find(|protocol| RESERVED_PROTOCOL_IDS.contains(&protocol.as_str()))
        {
            return Err(SwarmError::ReservedProtocol {
                protocol_id: protocol.clone(),
            }
            .into());
        }
        #[cfg(feature = "relay-server")]
        if self.common.capabilities.relay_server.is_none()
            && !self.state.relay_server_announce_addrs.is_empty()
        {
            return Err(EndpointOptionsError::RelayAnnounceWithoutServer.into());
        }
        #[cfg(all(feature = "relay-server", feature = "quic"))]
        if let Some(mesh) = &self.state.relay_mesh {
            self.validate_relay_mesh(mesh)?;
        }
        #[cfg(feature = "quic")]
        if self.ca_webtransport_certificate()
            && !self
                .state
                .listen_addrs
                .iter()
                .any(Multiaddr::is_webtransport)
        {
            return Err(EndpointOptionsError::WebTransportCertificateWithoutListener.into());
        }
        #[cfg(feature = "relay-server")]
        check_webtransport_announce(
            &self.state.relay_server_announce_addrs,
            self.ca_webtransport_certificate(),
        )
        .map_err(|error| BindError::RelayServerAnnounce(Box::new(error)))?;
        Ok(())
    }

    /// The relay-mesh checks [`Self::relay_mesh`] documents.
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    fn validate_relay_mesh(&self, mesh: &RelayMeshConfig) -> Result<(), EndpointOptionsError> {
        if self.common.capabilities.relay_server.is_none() {
            return Err(EndpointOptionsError::RelayMeshWithoutServer);
        }
        if self.state.keypair.as_ref() == Some(&mesh.identity) {
            return Err(EndpointOptionsError::RelayMeshPublicIdentity);
        }
        let backbone_shape = |address: &Multiaddr| {
            address.is_quic_transport()
                && matches!(
                    address.protocols().first(),
                    Some(Protocol::Ip4(_) | Protocol::Ip6(_))
                )
        };
        if let Some(addr) = mesh.listen.iter().find(|address| !backbone_shape(address)) {
            return Err(EndpointOptionsError::UnsupportedListenShape {
                addr: addr.clone(),
                expected: "a relay-mesh backbone `/ip4|ip6/<ip>/udp/<port>/quic-v1` address",
            });
        }
        if let Some(addr) = mesh
            .members
            .iter()
            .find(|member| !backbone_shape(member.transport()))
        {
            return Err(EndpointOptionsError::RelayMeshMember { addr: addr.clone() });
        }
        Ok(())
    }

    /// Whether WebTransport presents a CA-signed certificate rather than the
    /// derived self-signed ones.
    #[cfg(any(feature = "quic", feature = "relay-server"))]
    fn ca_webtransport_certificate(&self) -> bool {
        #[cfg(feature = "quic")]
        return matches!(
            self.state.webtransport_certificates,
            WebTransportCertificates::Provided { .. }
        );
        #[cfg(not(feature = "quic"))]
        false
    }

    /// Moves the capability intent out for Endpoint setup, which applies
    /// every default; the relay server joins it with its announce addresses.
    #[cfg_attr(
        not(all(feature = "relay-server", feature = "quic")),
        expect(unused_variables, reason = "only a relay mesh signs with the identity")
    )]
    fn take_capabilities(&mut self, keypair: &Ed25519Keypair) -> Capabilities {
        #[cfg_attr(
            not(feature = "relay-server"),
            expect(unused_mut, reason = "only the relay server joins here")
        )]
        let mut capabilities = std::mem::take(&mut self.common.capabilities);
        #[cfg(feature = "relay-server")]
        if let Some(setup) = capabilities.relay_server.as_mut() {
            #[cfg(feature = "quic")]
            if let Some(mesh) = &self.state.relay_mesh {
                let mut signed =
                    minip2p_relay_server::mesh::MeshConfig::new(keypair, &mesh.identity.peer_id());
                if let Some(given) = &setup.config.mesh {
                    signed.max_directory_entries_per_member =
                        given.max_directory_entries_per_member;
                }
                setup.config.mesh = Some(signed);
            }
            setup.announce_addrs = std::mem::take(&mut self.state.relay_server_announce_addrs);
        }
        capabilities
    }

    /// Everything bind checks before a socket opens: the options, then the
    /// capabilities through Endpoint setup. Returns the identity and the
    /// validated capabilities.
    fn prepare(&mut self) -> Result<(Ed25519Keypair, setup::Validated), BindError> {
        self.validate()?;
        let keypair = self
            .state
            .keypair
            .take()
            .unwrap_or_else(Ed25519Keypair::generate);
        let capabilities = setup::validate(
            self.take_capabilities(&keypair),
            STD_PLATFORM,
            &keypair.peer_id(),
        )?;
        Ok((keypair, capabilities))
    }

    /// Binds over an already-bound transport set, for the crate's tests.
    #[cfg(test)]
    pub(crate) fn bind_over(mut self, transport: TransportSet) -> Result<Endpoint, BindError> {
        let (keypair, capabilities) = self.prepare()?;
        build_endpoint(self, keypair, transport, capabilities)
    }
}

#[cfg(any(feature = "quic", feature = "tcp"))]
pub(super) fn validate_listen_multiaddr(address: &Multiaddr) -> Result<(), EndpointOptionsError> {
    let unsupported = |expected| EndpointOptionsError::UnsupportedListenShape {
        addr: address.clone(),
        expected,
    };
    if address.protocols().is_empty() {
        return Err(unsupported("a non-empty transport address"));
    }
    if address
        .protocols()
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_) | Protocol::P2pCircuit))
    {
        return Err(unsupported(
            "a transport address without /p2p or /p2p-circuit (those belong on dial targets)",
        ));
    }

    let ip_host = matches!(
        address.protocols().first(),
        Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
    );
    if !ip_host {
        return Err(unsupported(
            "an /ip4 or /ip6 host (DNS names are dial-only)",
        ));
    }

    #[cfg(feature = "quic")]
    if address.is_quic_transport() {
        return Ok(());
    }
    #[cfg(feature = "quic")]
    if address.is_webtransport() {
        if address.certhashes().next().is_some() {
            return Err(unsupported(
                "`/ip4|ip6/udp/<port>/quic-v1/webtransport` without /certhash \
                 (the node's own certificate supplies it)",
            ));
        }
        return Ok(());
    }
    #[cfg(feature = "tcp")]
    if address.is_tcp_transport() {
        return Ok(());
    }

    #[cfg(all(feature = "quic", feature = "tcp"))]
    let expected =
        "`/ip4|ip6/udp/<port>/quic-v1`, `…/quic-v1/webtransport` or `/ip4|ip6/tcp/<port>`";
    #[cfg(all(feature = "quic", not(feature = "tcp")))]
    let expected = "`/ip4|ip6/udp/<port>/quic-v1` or `…/quic-v1/webtransport`";
    #[cfg(all(feature = "tcp", not(feature = "quic")))]
    let expected = "`/ip4|ip6/tcp/<port>`";
    Err(unsupported(expected))
}

#[cfg(feature = "quic")]
pub(super) fn listen_ip_family(address: &Multiaddr) -> Option<IpFamily> {
    match address.protocols().first() {
        Some(Protocol::Ip4(_)) => Some(IpFamily::Ipv4),
        Some(Protocol::Ip6(_)) => Some(IpFamily::Ipv6),
        _ => None,
    }
}

/// Whether a listen address is one the QUIC transport binds: `quic-v1` or
/// WebTransport.
#[cfg(feature = "quic")]
pub(super) fn is_quic_listen(address: &Multiaddr) -> bool {
    address.is_quic_transport() || address.is_webtransport()
}

/// QUIC binds one socket per family, which may serve one `quic-v1` and one
/// WebTransport address: a second address of a family must name the same
/// host and port as the first, in the other shape.
#[cfg(feature = "quic")]
pub(super) fn reject_duplicate_quic_family(
    existing: &[Multiaddr],
    next: &Multiaddr,
) -> Result<(), EndpointOptionsError> {
    let Some(family) = listen_ip_family(next) else {
        return Ok(());
    };
    let socket = |address: &Multiaddr| address.protocols().get(..2).map(<[Protocol]>::to_vec);
    if existing
        .iter()
        .filter(|address| is_quic_listen(address))
        .filter(|address| listen_ip_family(address) == Some(family))
        .any(|address| {
            address.is_webtransport() == next.is_webtransport() || socket(address) != socket(next)
        })
    {
        return Err(EndpointOptionsError::DuplicateQuicFamily {
            addr: next.clone(),
            family,
        });
    }
    Ok(())
}

/// Browsers pin a self-signed WebTransport certificate by the address's
/// `/certhash` and check a CA-signed one by its chain, so a WebTransport
/// announce address carries a hash exactly when the certificate is derived.
#[cfg(feature = "relay-server")]
#[expect(
    clippy::result_large_err,
    reason = "The error owns the rejected announce address for actionable host diagnostics."
)]
pub(super) fn check_webtransport_announce(
    addrs: &[Multiaddr],
    ca_certificate: bool,
) -> Result<(), RelayServerAddressError> {
    for (index, address) in addrs.iter().enumerate() {
        if !address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::WebTransport))
        {
            continue;
        }
        let reason = match (ca_certificate, address.certhashes().next().is_some()) {
            (false, false) => RelayServerAddressErrorKind::MissingCerthash,
            (true, true) => RelayServerAddressErrorKind::UnexpectedCerthash,
            _ => continue,
        };
        return Err(RelayServerAddressError {
            index,
            address: address.clone(),
            reason,
        });
    }
    Ok(())
}

/// Brings up every requested transport behind one set.
///
/// Listen multiaddresses are grouped by transport shape: compatible QUIC IPv4
/// and IPv6 addresses become one QUIC member, and every `/tcp` address lands on
/// one TCP member. Members are inserted in the order their shape first appears,
/// so `listen_all` reports addresses in configuration order.
#[cfg_attr(
    not(any(feature = "quic", feature = "tcp")),
    expect(
        unused_mut,
        unused_variables,
        reason = "without a transport feature there is nothing to bind"
    )
)]
pub(super) fn bind_transports(
    options: &EndpointBuilder,
    keypair: &Ed25519Keypair,
) -> Result<(TransportSet, CertificateHandle), BindError> {
    let mut set = TransportSet::new();
    #[cfg_attr(
        not(feature = "quic"),
        expect(unused_mut, reason = "only a QUIC transport sets it")
    )]
    let mut certificate: CertificateHandle = None;

    #[cfg(any(feature = "quic", feature = "tcp"))]
    {
        let addrs = &options.state.listen_addrs;
        #[cfg(feature = "quic")]
        let quic_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| is_quic_listen(address))
            .collect();
        #[cfg(feature = "tcp")]
        let tcp_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| address.is_tcp_transport())
            .collect();
        let quic_first = addrs
            .first()
            .is_none_or(|address| address.transport_kind() == Some(TransportKind::Quic));
        let order = if quic_first {
            [true, false]
        } else {
            [false, true]
        };
        for want_quic in order {
            #[cfg(feature = "quic")]
            if want_quic && !quic_addrs.is_empty() {
                let config = QuicNodeConfig::new(keypair.clone())
                    .with_limits(options.state.quic_limits.clone())
                    .with_webtransport_certificates(
                        options.state.webtransport_certificates.clone(),
                    );
                let addresses: Vec<Multiaddr> =
                    quic_addrs.iter().map(|&address| address.clone()).collect();
                let transport = QuicTransport::bind(config, &addresses).map_err(BindError::Quic)?;
                certificate = transport.webtransport_certificate_handle();
                let namespaces = transport.namespaces();
                insert_member(&mut set, TransportKind::Quic, namespaces, transport)?;
            }
            #[cfg(feature = "tcp")]
            if !want_quic && !tcp_addrs.is_empty() {
                let transport = bind_tcp_member(options, keypair, &tcp_addrs)?;
                let namespace = transport.namespace();
                insert_member(&mut set, TransportKind::Tcp, [namespace], transport)?;
            }
        }
    }

    if set.is_empty() {
        return Err(EndpointOptionsError::NoTransport.into());
    }
    Ok((set, certificate))
}

/// What [`Endpoint::set_webtransport_certificate_pem`] replaces a CA-signed
/// certificate through: the QUIC transport's handle, since the transport
/// itself is boxed in the [`TransportSet`].
#[cfg(feature = "quic")]
pub(super) type CertificateHandle = Option<minip2p_quic::WebTransportCertificateHandle>;
#[cfg(not(feature = "quic"))]
pub(super) type CertificateHandle = Option<core::convert::Infallible>;

/// A certificate chain (leaf first) and its one private key from PEM, or
/// what is wrong with them.
#[cfg(feature = "quic")]
pub(super) fn parse_certificate_pem(
    chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<
    (
        Vec<minip2p_quic::pki_types::CertificateDer<'static>>,
        minip2p_quic::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    use minip2p_quic::pki_types::pem::PemObject;
    use minip2p_quic::pki_types::{CertificateDer, PrivateKeyDer};

    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("certificate chain: {error}"))?;
    if chain.is_empty() {
        return Err("the certificate chain has no `BEGIN CERTIFICATE` section".into());
    }
    let mut keys = PrivateKeyDer::pem_slice_iter(key_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("private key: {error}"))?;
    match keys.len() {
        1 => Ok((chain, keys.remove(0))),
        0 => Err(
            "the key PEM has no `BEGIN PRIVATE KEY`, `BEGIN EC PRIVATE KEY` or \
                  `BEGIN RSA PRIVATE KEY` section"
                .into(),
        ),
        count => Err(format!(
            "the key PEM has {count} private keys; pass only the leaf's"
        )),
    }
}

/// Builds the one TCP transport, listening on every `/tcp` address asked for.
#[cfg(feature = "tcp")]
pub(super) fn bind_tcp_member(
    options: &EndpointBuilder,
    keypair: &Ed25519Keypair,
    tcp_addrs: &[&Multiaddr],
) -> Result<TcpTransport<StdTcpProvider, StdEntropy>, BindError> {
    let namespace = options.state.tcp_config.namespace;
    if namespace != ConnectionNamespace::TCP_IPV4 && namespace != ConnectionNamespace::TCP_IPV6 {
        return Err(EndpointOptionsError::TcpNamespace { namespace }.into());
    }

    let mut transport = TcpTransport::with_config(
        StdTcpProvider::new(),
        keypair.clone(),
        StdEntropy::new(),
        options.state.tcp_config.clone(),
    )
    .map_err(EndpointOptionsError::InvalidLimit)?;
    for addr in tcp_addrs {
        transport.listen(addr).map_err(BindError::Listen)?;
    }
    Ok(transport)
}

#[cfg(any(feature = "quic", feature = "tcp"))]
pub(super) fn insert_member<T: minip2p_transport::BlockingTransport + Send + 'static>(
    set: &mut TransportSet,
    kind: TransportKind,
    namespaces: impl IntoIterator<Item = ConnectionNamespace>,
    transport: T,
) -> Result<(), BindError> {
    set.insert(kind, namespaces, Box::new(transport))
        .map_err(|rejected| {
            let (error, _transport) = rejected.into_parts();
            EndpointOptionsError::TransportConflict(error).into()
        })
}

/// Wraps the bound transports in the OS resources the endpoint drives them
/// with (circuits, the readiness poll, mDNS sockets, Name resolution), and
/// installs the validated capabilities through Endpoint setup.
pub(super) fn build_endpoint(
    options: EndpointBuilder,
    keypair: Ed25519Keypair,
    transport: TransportSet,
    capabilities: setup::Validated,
) -> Result<Endpoint, BindError> {
    #[cfg(feature = "relay-server")]
    let ca_webtransport_certificate = options.ca_webtransport_certificate();
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    let relay_mesh = options.state.relay_mesh.clone().map(|mesh| {
        (
            mesh,
            options.common.agent_version.clone(),
            options.common.timeouts,
        )
    });
    let (swarm, parts) =
        options
            .common
            .into_parts(&keypair)
            .map_err(|error| BindError::Invariant {
                reason: match error {
                    crate::DriverError::Invariant { reason } => reason,
                    _ => crate::protocols::TABLE_FULL,
                },
            })?;
    #[cfg(feature = "relay")]
    let mut transport = minip2p_circuit::CircuitTransport::with_limits(
        transport,
        keypair.clone(),
        StdEntropy::new(),
        options.state.circuit_limits.clone(),
    )
    .map_err(EndpointOptionsError::InvalidLimit)?;
    #[cfg(not(feature = "relay"))]
    let mut transport = transport;
    let mut poll = SharedPoll::new()
        .map_err(|error| BindError::readiness_poll("opening the readiness poll", &error))?;
    poll.attach(&mut transport)
        .map_err(|error| BindError::readiness_poll("attaching the transport", &error))?;
    let resolver = dial::Resolver::new(poll.wake_handle());
    #[cfg(feature = "mdns")]
    let mdns_sockets = match capabilities.mdns() {
        Some(config) => {
            let mut sockets =
                minip2p_mdns::MdnsSockets::new(config).map_err(BindError::MdnsSocket)?;
            poll.attach_host_source(&mut sockets)
                .map_err(|error| BindError::readiness_poll("attaching the mDNS sockets", &error))?;
            Some(sockets)
        }
        None => None,
    };
    let mut engine = parts.engine(swarm.build_core(transport, StdEntropy::new())?);
    setup::install(
        &mut engine,
        capabilities,
        &keypair,
        #[cfg(feature = "relay")]
        Some(CircuitOps::circuit_transport()),
        #[cfg(feature = "mdns")]
        mdns_sockets,
    )?;
    #[cfg(all(feature = "relay-server", feature = "quic"))]
    if let Some((mesh, agent_version, timeouts)) = relay_mesh {
        let relay_server = engine.relay_server.as_mut().ok_or(BindError::Invariant {
            reason: "a validated relay mesh has no relay server",
        })?;
        relay_server.backbone = Some(bind_backbone(mesh, agent_version, timeouts, &mut poll)?);
    }
    Ok(Endpoint {
        engine,
        platform: StdPlatform {
            clock: StdClock::new(),
            resolver,
            #[cfg(feature = "relay-server")]
            ca_webtransport_certificate,
            #[cfg(feature = "quic")]
            webtransport_certificate: None,
            poll,
            #[cfg(all(test, feature = "quic"))]
            raw_events: std::collections::VecDeque::new(),
        },
        closed_at: None,
    })
}

/// Binds a relay mesh's backbone: a swarm under the backbone identity, over
/// QUIC in the mesh connection namespaces (so the relay agent tells its
/// connections apart), listening and attached to the endpoint's poll as a
/// host source: its readiness wakes the wait, and each batch polls it.
#[cfg(all(feature = "relay-server", feature = "quic"))]
pub(super) fn bind_backbone(
    mesh: RelayMeshConfig,
    agent_version: String,
    timeouts: SwarmTimeouts,
    poll: &mut SharedPoll,
) -> Result<crate::relay_mesh::Backbone, BindError> {
    let config = QuicNodeConfig::new(mesh.identity.clone())
        .with_namespaces(minip2p_quic::QuicNamespaces::MESH);
    let mut transport = QuicTransport::bind(config, &mesh.listen).map_err(BindError::RelayMesh)?;
    poll.attach_host_source(&mut transport)
        .map_err(|error| BindError::readiness_poll("attaching the relay-mesh backbone", &error))?;
    let mut core = SwarmBuilder::new(&mesh.identity)
        .agent_version(agent_version)
        .timeouts(timeouts)
        .build_core(transport, StdEntropy::new())?;
    minip2p_relay_server::mesh::register_backbone_roles(&mut core)?;
    core.listen_on_bound_addrs().map_err(|error| match error {
        Error::Transport(error) => BindError::Listen(error),
        _ => BindError::Invariant {
            reason: "listening on the backbone's bound addresses failed outside the transport",
        },
    })?;
    Ok(crate::relay_mesh::Backbone::new(core, mesh.members))
}
