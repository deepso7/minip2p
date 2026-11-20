use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use minip2p::{Endpoint, Multiaddr, PeerAddr, Protocol, RateLimit, RelayServerConfig};

/// What the relay runs with, from flags or from a `--config` file.
#[derive(Debug, PartialEq)]
pub struct Options {
    /// Exact QUIC binds; empty selects automatic IPv4/IPv6 binding.
    pub quic_binds: Vec<SocketAddr>,
    /// Exact TCP binds; empty selects automatic IPv4/IPv6 binding.
    pub tcp_binds: Vec<SocketAddr>,
    pub key_path: Option<PathBuf>,
    pub announce_addrs: Vec<Multiaddr>,
    pub accepting: bool,
    /// Also serve WebTransport (browsers) on every QUIC socket.
    pub webtransport: bool,
    /// A CA-signed WebTransport certificate's chain and key PEM files.
    pub webtransport_certificate: Option<CertificatePaths>,
    /// How often to check the certificate files for a renewal.
    pub webtransport_reload_interval: Duration,
    pub config: RelayServerConfig,
    /// Relay-mesh backbone settings; `None` runs a standalone relay.
    pub mesh: Option<MeshOptions>,
}

/// `--mesh-key`, `--mesh-listen` and `--mesh-member`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeshOptions {
    /// The backbone identity, loaded or created like `--key`.
    pub key_path: PathBuf,
    /// Exact backbone binds; empty selects UDP 19877 on IPv4 and IPv6.
    pub listen: Vec<SocketAddr>,
    /// Backbone addresses of the members this node dials; its own entry is
    /// skipped. Members it doesn't list can still dial it.
    pub members: Vec<PeerAddr>,
}

/// `--webtransport-cert` and `--webtransport-key`, which come as a pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificatePaths {
    pub chain: PathBuf,
    pub key: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            quic_binds: Vec::new(),
            tcp_binds: Vec::new(),
            key_path: None,
            announce_addrs: Vec::new(),
            accepting: true,
            webtransport: false,
            webtransport_certificate: None,
            webtransport_reload_interval: Duration::from_secs(30),
            config: RelayServerConfig::default(),
            mesh: None,
        }
    }
}

/// Parses the relay's flags, or `--config PATH` alone, which reads them all
/// from a file (see [`crate::config`]).
pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--config") {
        return match args.as_slice() {
            [flag, path] if flag == "--config" => crate::config::load(Path::new(path)),
            _ => Err(
                "--config PATH excludes every other option; set them in the config file instead"
                    .into(),
            ),
        };
    }
    let mut options = Options::default();
    let (mut certificate, mut key) = (None, None);
    let (mut mesh_key, mut mesh_listen, mut mesh_members) = (None, Vec::new(), Vec::new());
    let mut args = args.into_iter();
    while let Some(flag) = args.next() {
        let value = |args: &mut std::vec::IntoIter<String>| next_value(&flag, args);
        match flag.as_str() {
            "--help" | "-h" => return Err(usage().into()),
            "--quic" => options.quic_binds.push(socket(&flag, value(&mut args)?)?),
            "--tcp" => options.tcp_binds.push(socket(&flag, value(&mut args)?)?),
            "--key" => options.key_path = Some(value(&mut args)?.into()),
            "--announce" => options.announce_addrs.push(
                value(&mut args)?
                    .parse()
                    .map_err(|error| format!("invalid --announce multiaddr: {error}"))?,
            ),
            "--paused" => options.accepting = false,
            "--mesh-key" => mesh_key = Some(value(&mut args)?.into()),
            "--mesh-listen" => mesh_listen.push(socket(&flag, value(&mut args)?)?),
            "--mesh-member" => mesh_members.push(
                value(&mut args)?
                    .parse()
                    .map_err(|error| format!("invalid --mesh-member peer address: {error}"))?,
            ),
            "--webtransport" => options.webtransport = true,
            "--webtransport-cert" => certificate = Some(value(&mut args)?.into()),
            "--webtransport-key" => key = Some(value(&mut args)?.into()),
            "--webtransport-reload-secs" => {
                options.webtransport_reload_interval =
                    Duration::from_secs(number(&flag, value(&mut args)?)?)
            }
            "--max-reservations" => {
                options.config.max_reservations = number(&flag, value(&mut args)?)?
            }
            "--max-reservations-per-ip" => {
                options.config.max_reservations_per_ip = number(&flag, value(&mut args)?)?
            }
            "--reservation-duration" => {
                options.config.reservation_duration_secs = number(&flag, value(&mut args)?)?
            }
            "--max-circuits" => options.config.max_circuits = number(&flag, value(&mut args)?)?,
            "--max-circuits-per-peer" => {
                options.config.max_circuits_per_peer = number(&flag, value(&mut args)?)?
            }
            "--max-circuits-per-ip" => {
                options.config.max_circuits_per_ip = number(&flag, value(&mut args)?)?
            }
            "--max-circuit-duration" => {
                options.config.max_circuit_duration_secs = number(&flag, value(&mut args)?)?
            }
            "--max-circuit-bytes" => {
                options.config.max_circuit_bytes = number(&flag, value(&mut args)?)?
            }
            "--max-pending-hop" => {
                options.config.max_pending_hop_requests_per_connection =
                    number(&flag, value(&mut args)?)?
            }
            "--max-pending-stop" => {
                options.config.max_pending_stop_requests_per_connection =
                    number(&flag, value(&mut args)?)?
            }
            "--control-timeout-ms" => {
                options.config.control_stream_timeout_ms = number(&flag, value(&mut args)?)?
            }
            "--reservation-peer-rate" => {
                options.config.reservation_rate_limit_per_peer = rate(&flag, value(&mut args)?)?
            }
            "--reservation-ip-rate" => {
                options.config.reservation_rate_limit_per_ip = rate(&flag, value(&mut args)?)?
            }
            "--circuit-peer-rate" => {
                options.config.circuit_rate_limit_per_peer = rate(&flag, value(&mut args)?)?
            }
            "--circuit-ip-rate" => {
                options.config.circuit_rate_limit_per_ip = rate(&flag, value(&mut args)?)?
            }
            "--max-rate-limit-entries" => {
                options.config.max_rate_limit_entries = number(&flag, value(&mut args)?)?
            }
            _ => return Err(format!("unknown option {flag}\n\n{}", usage())),
        }
    }
    options.webtransport_certificate = match (certificate, key) {
        (Some(chain), Some(key)) => Some(CertificatePaths { chain, key }),
        (None, None) => None,
        _ => {
            return Err("--webtransport-cert and --webtransport-key must be given together".into());
        }
    };
    options.webtransport |= options.webtransport_certificate.is_some();
    options.mesh = match mesh_key {
        Some(key_path) => Some(MeshOptions {
            key_path,
            listen: mesh_listen,
            members: mesh_members,
        }),
        None if mesh_listen.is_empty() && mesh_members.is_empty() => None,
        None => return Err("--mesh-listen and --mesh-member need --mesh-key".into()),
    };
    validate(&options)?;
    Ok(options)
}

/// The checks flags and config files share, so the relay refuses a bad
/// setting before it binds anything. Errors name the flag and its field.
pub(crate) fn validate(options: &Options) -> Result<(), String> {
    for ipv4 in [true, false] {
        if options
            .quic_binds
            .iter()
            .filter(|bind| bind.is_ipv4() == ipv4)
            .count()
            > 1
        {
            return Err("--quic (quic) accepts at most one IPv4 and one IPv6 address".into());
        }
    }
    if !options.announce_addrs.is_empty() {
        Endpoint::builder()
            .relay_server_announce_addrs(options.announce_addrs.clone())
            .map_err(|error| format!("invalid --announce (announce): {error}"))?;
    }
    let ca_certificate = options.webtransport_certificate.is_some();
    for address in &options.announce_addrs {
        if address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::WebTransport))
            && address.certhashes().next().is_some() == ca_certificate
        {
            return Err(if ca_certificate {
                format!(
                    "WebTransport announce {address} must not carry a /certhash with a CA certificate"
                )
            } else {
                format!(
                    "WebTransport announce {address} needs the /certhash from the `webtransport=` log line, or a CA certificate"
                )
            });
        }
    }
    if let Some(mesh) = &options.mesh {
        check_mesh(&mesh.listen, &mesh.members)?;
        if options.key_path.is_none() {
            return Err(
                "the mesh needs a persistent identity (--key, or key in the config): every mesh node loads the same one"
                    .into(),
            );
        }
    }
    options.config.validate().map_err(|error| error.to_string())
}

fn next_value(flag: &str, args: &mut std::vec::IntoIter<String>) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n\n{}", usage()))
}

fn number<T: core::str::FromStr>(flag: &str, value: String) -> Result<T, String> {
    #[expect(
        clippy::map_err_ignore,
        reason = "the CLI reports one compact, flag-specific parse error"
    )]
    value
        .parse()
        .map_err(|_| format!("{flag} requires a non-negative integer, got {value:?}"))
}

/// Checks mesh settings the relay would only reject once bound.
fn check_mesh(listen: &[SocketAddr], members: &[PeerAddr]) -> Result<(), String> {
    for ipv4 in [true, false] {
        let mut family = listen.iter().filter(|address| address.is_ipv4() == ipv4);
        if let Some(first) = family.next()
            && family.any(|address| address != first)
        {
            return Err(
                "--mesh-listen ([mesh] listen) accepts at most one IPv4 and one IPv6 address"
                    .into(),
            );
        }
    }
    for member in members {
        if !matches!(
            member.transport().protocols(),
            [
                Protocol::Ip4(_) | Protocol::Ip6(_),
                Protocol::Udp(_),
                Protocol::QuicV1
            ]
        ) {
            return Err(format!(
                "mesh member {member} must be /ip4|ip6/IP/udp/PORT/quic-v1/p2p/BACKBONE_ID"
            ));
        }
    }
    Ok(())
}

/// Resolves one `HOST:PORT` bind to the single socket address it binds: the
/// resolver's first answer. One flag is one socket, as before binds became
/// listen multiaddrs; repeat the flag (or pass IPs) to bind both families.
pub(crate) fn socket(flag: &str, value: String) -> Result<SocketAddr, String> {
    value
        .to_socket_addrs()
        .map_err(|error| {
            format!("{flag} requires a HOST:PORT socket address, got {value:?}: {error}")
        })?
        .next()
        .ok_or_else(|| format!("{flag} {value:?} resolved to no address"))
}

pub(crate) fn rate(flag: &str, value: String) -> Result<Option<RateLimit>, String> {
    if value == "off" {
        return Ok(None);
    }
    let (capacity, interval) = value
        .split_once('/')
        .ok_or_else(|| format!("{flag} requires CAPACITY/REFILL_MS or off"))?;
    Ok(Some(RateLimit {
        capacity: number(flag, capacity.into())?,
        refill_interval_ms: number(flag, interval.into())?,
    }))
}

pub fn usage() -> &'static str {
    "usage: minip2p-relay [options]\n       minip2p-relay --config PATH\n       minip2p-relay service <COMMAND>\n\nDefaults try QUIC and TCP on IPv4 and IPv6 port 19876, falling back to the available family.\n\n--config PATH                  read every option below from a TOML file instead (no other flags)\n--quic HOST:PORT               exact QUIC socket bind (repeatable; replaces automatic binds)\n--tcp HOST:PORT                exact TCP socket bind (repeatable; replaces automatic binds)\n--key PATH                     load/create persistent Ed25519 identity\n--announce MULTIADDR           explicit public address (repeatable; WebTransport ones need their /certhash without --webtransport-cert, and none with it)\n--webtransport                 also serve WebTransport (browsers) on the QUIC port\n--webtransport-cert PATH       CA-signed WebTransport certificate chain (PEM); implies --webtransport\n--webtransport-key PATH        the --webtransport-cert private key (PEM); required with it\n--webtransport-reload-secs N   how often to check both files and serve a renewed certificate (default 30)\n--paused                       start with new admissions paused\n--mesh-key PATH                load/create this node's relay-mesh backbone identity; enables the mesh\n--mesh-listen HOST:PORT        exact backbone UDP bind (repeatable; default 0.0.0.0:19877 and [::]:19877)\n--mesh-member PEER_ADDR        a member's /ip4|ip6/.../udp/PORT/quic-v1/p2p/BACKBONE_ID (repeatable; own entry skipped)\n--max-reservations N           reservation capacity\n--max-reservations-per-ip N    reservations per IPv4 address or IPv6 /64\n--reservation-duration SECS    reservation lifetime\n--max-circuits N               circuit capacity\n--max-circuits-per-peer N      per-endpoint circuit capacity\n--max-circuits-per-ip N        circuits per IPv4 address or IPv6 /64\n--max-circuit-duration SECS    circuit lifetime (0 = unlimited)\n--max-circuit-bytes BYTES      per-direction bytes (0 = unlimited)\n--max-pending-hop N            pending HOP controls per connection\n--max-pending-stop N           pending STOP controls per connection\n--control-timeout-ms MS        end-to-end control timeout\n--reservation-peer-rate R      CAPACITY/REFILL_MS or off\n--reservation-ip-rate R        CAPACITY/REFILL_MS or off\n--circuit-peer-rate R          CAPACITY/REFILL_MS or off\n--circuit-ip-rate R            CAPACITY/REFILL_MS or off\n--max-rate-limit-entries N     keys each rate limiter tracks\n-h, --help                     show this help\n-V, --version                  show the release version\n\nService management:\n  minip2p-relay service install (--hostname HOSTNAME | --config PATH) [--import-key PATH]\n  minip2p-relay service status | logs | restart | uninstall"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_keep_the_three_line_hosting_path() {
        let options = parse(Vec::<String>::new()).unwrap();
        assert!(options.quic_binds.is_empty());
        assert!(options.tcp_binds.is_empty());
        assert!(options.accepting);
        assert!(options.key_path.is_none());
        assert!(options.announce_addrs.is_empty());
        assert!(!options.webtransport);
        assert!(options.webtransport_certificate.is_none());
        assert_eq!(options.config, RelayServerConfig::default());
        assert!(options.mesh.is_none());
    }

    #[test]
    fn accepts_repeatable_custom_transport_binds() {
        let options = parse([
            "--quic".into(),
            "127.0.0.1:4101".into(),
            "--quic".into(),
            "[::1]:4101".into(),
            "--tcp".into(),
            "127.0.0.1:4201".into(),
            "--tcp".into(),
            "[::1]:4201".into(),
        ])
        .unwrap();

        let text = |binds: &[SocketAddr]| binds.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(text(&options.quic_binds), ["127.0.0.1:4101", "[::1]:4101"]);
        assert_eq!(text(&options.tcp_binds), ["127.0.0.1:4201", "[::1]:4201"]);
    }

    #[test]
    fn rejects_more_than_two_quic_binds() {
        let error = parse([
            "--quic".into(),
            "127.0.0.1:4101".into(),
            "--quic".into(),
            "[::1]:4101".into(),
            "--quic".into(),
            "127.0.0.2:4101".into(),
        ])
        .unwrap_err();

        assert!(error.contains("at most one IPv4 and one IPv6"), "{error}");
    }

    #[test]
    fn rejects_two_quic_binds_in_one_family() {
        let error = parse([
            "--quic".into(),
            "127.0.0.1:4101".into(),
            "--quic".into(),
            "127.0.0.2:4101".into(),
        ])
        .unwrap_err();
        assert!(error.contains("at most one IPv4 and one IPv6"), "{error}");
    }

    #[test]
    fn rejects_a_wildcard_announce_before_binding() {
        let error = parse(["--announce".into(), "/ip4/0.0.0.0/tcp/4001".into()]).unwrap_err();
        assert!(error.contains("invalid --announce"), "{error}");
    }

    #[test]
    fn a_hashless_webtransport_announce_needs_a_ca_certificate() {
        let announce = "/dns/relay.example.com/udp/19876/quic-v1/webtransport";
        let error = parse([
            "--webtransport".into(),
            "--announce".into(),
            announce.into(),
        ])
        .unwrap_err();
        assert!(error.contains("needs the /certhash"), "{error}");
        parse([
            "--webtransport-cert".into(),
            "c.pem".into(),
            "--webtransport-key".into(),
            "k.pem".into(),
            "--announce".into(),
            announce.into(),
        ])
        .unwrap();
    }

    #[test]
    fn resolves_a_hostname_bind_to_one_address() {
        let options = parse(["--tcp".into(), "localhost:4201".into()]).unwrap();
        assert_eq!(options.tcp_binds.len(), 1);
        let bind = options.tcp_binds[0];
        assert!(bind.ip().is_loopback() && bind.port() == 4201, "{bind}");
    }

    #[test]
    fn rejects_a_non_socket_bind_address() {
        let error = parse(["--tcp".into(), "/ip4/127.0.0.1/tcp/4201".into()]).unwrap_err();
        assert!(error.contains("--tcp requires a HOST:PORT"), "{error}");
    }

    #[test]
    fn rejects_invalid_configuration_before_binding() {
        let error = parse(["--control-timeout-ms".into(), "0".into()]).unwrap_err();
        assert!(error.contains("control_stream_timeout_ms"), "{error}");
    }

    #[test]
    fn parses_operational_overrides_and_disabled_rate_limit() {
        let options = parse([
            "--announce".into(),
            "/ip4/203.0.113.4/tcp/4001".into(),
            "--paused".into(),
            "--webtransport".into(),
            "--max-circuits".into(),
            "7".into(),
            "--max-circuits-per-ip".into(),
            "3".into(),
            "--reservation-peer-rate".into(),
            "3/250".into(),
            "--circuit-ip-rate".into(),
            "off".into(),
        ])
        .unwrap();
        assert_eq!(
            options.announce_addrs,
            ["/ip4/203.0.113.4/tcp/4001".parse().unwrap()]
        );
        assert!(!options.accepting);
        assert!(options.webtransport);
        assert_eq!(options.config.max_circuits, 7);
        assert_eq!(options.config.max_circuits_per_ip, 3);
        assert_eq!(
            options.config.reservation_rate_limit_per_peer,
            Some(RateLimit {
                capacity: 3,
                refill_interval_ms: 250,
            })
        );
        assert_eq!(options.config.circuit_rate_limit_per_ip, None);
    }

    #[test]
    fn a_webtransport_certificate_implies_webtransport() {
        let options = parse([
            "--webtransport-cert".into(),
            "fullchain.pem".into(),
            "--webtransport-key".into(),
            "privkey.pem".into(),
        ])
        .unwrap();
        assert!(options.webtransport);
        assert_eq!(
            options.webtransport_certificate,
            Some(CertificatePaths {
                chain: "fullchain.pem".into(),
                key: "privkey.pem".into(),
            })
        );
    }

    #[test]
    fn a_webtransport_certificate_needs_its_key_and_vice_versa() {
        for flag in ["--webtransport-cert", "--webtransport-key"] {
            let error = parse([flag.into(), "file.pem".into()]).unwrap_err();
            assert!(error.contains("must be given together"), "{error}");
        }
    }

    #[test]
    fn parses_mesh_flags() {
        let options = parse([
            "--key".into(),
            "identity.key".into(),
            "--mesh-key".into(),
            "mesh.key".into(),
            "--mesh-listen".into(),
            "127.0.0.1:4301".into(),
            "--mesh-member".into(),
            "/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".into(),
        ])
        .unwrap();
        assert_eq!(
            options.mesh,
            Some(MeshOptions {
                key_path: "mesh.key".into(),
                listen: vec!["127.0.0.1:4301".parse().unwrap()],
                members: vec!["/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".parse().unwrap()],
            })
        );
    }

    #[test]
    fn rejects_incomplete_mesh_flags() {
        let error = parse(["--mesh-key".into(), "mesh.key".into()]).unwrap_err();
        assert!(error.contains("persistent identity"), "{error}");
        for flag in ["--mesh-listen", "--mesh-member"] {
            let value = if flag == "--mesh-listen" {
                "127.0.0.1:4301"
            } else {
                "/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            };
            let error = parse([flag.into(), value.into()]).unwrap_err();
            assert!(error.contains("need --mesh-key"), "{error}");
        }
        let error = parse([
            "--mesh-member".into(),
            "/ip4/203.0.113.10/udp/19877/quic-v1".into(),
        ])
        .unwrap_err();
        assert!(error.contains("invalid --mesh-member"), "{error}");
    }

    #[test]
    fn check_mesh_rejects_what_the_relay_would_refuse_at_bind() {
        let dns: PeerAddr = "/dns4/relay.example.com/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
            .parse()
            .unwrap();
        let error = check_mesh(&[], &[dns]).unwrap_err();
        assert!(error.contains("must be /ip4|ip6"), "{error}");
        let listen: Vec<SocketAddr> = ["0.0.0.0:19877", "127.0.0.1:19878"]
            .iter()
            .map(|address| address.parse().unwrap())
            .collect();
        let error = check_mesh(&listen, &[]).unwrap_err();
        assert!(error.contains("at most one IPv4 and one IPv6"), "{error}");
    }
}
