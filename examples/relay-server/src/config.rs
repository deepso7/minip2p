//! `minip2p-relay --config PATH`: every relay option in one TOML file.
//!
//! Fields mirror the flags in [`cli::usage`]: `--max-circuits N` is
//! `[limits] max_circuits = N`, `--mesh-member` is `[mesh] members`, and so
//! on. Omitted fields keep the binary's defaults, unknown fields are an
//! error, and a `[webtransport]` or `[mesh]` section turns its feature on.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::cli::{self, CertificatePaths, MeshOptions, Options};

/// The port `hostname` announces: the relay's default QUIC and TCP port.
const DEFAULT_PORT: u16 = 19876;

/// A parsed config file, before its values are checked.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct File {
    /// Announces `/dns/<hostname>` on the default ports.
    pub hostname: Option<String>,
    /// `--key`
    pub key: Option<PathBuf>,
    /// `--quic`, one entry per bind.
    pub quic: Vec<String>,
    /// `--tcp`, one entry per bind.
    pub tcp: Vec<String>,
    /// `--announce`, after the `hostname` announcements.
    pub announce: Vec<String>,
    /// `--paused`
    pub paused: bool,
    /// `--webtransport` and its certificate flags.
    pub webtransport: Option<WebTransport>,
    /// The relay limits and rate limits.
    pub limits: Limits,
    /// `--mesh-key`, `--mesh-listen` and `--mesh-member`.
    pub mesh: Option<Mesh>,
}

/// `[webtransport]`: present serves WebTransport; `cert` and `key` select a
/// CA-signed certificate, and omitting both the identity-derived ones.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebTransport {
    /// `--webtransport-cert`
    pub cert: Option<PathBuf>,
    /// `--webtransport-key`
    pub key: Option<PathBuf>,
    /// `--webtransport-reload-secs`
    pub reload_secs: Option<u64>,
}

/// `[mesh]`: present joins a relay mesh.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mesh {
    /// `--mesh-key`; required, so the backbone identity is never ephemeral.
    pub key: Option<PathBuf>,
    /// `--mesh-listen`
    pub listen: Vec<String>,
    /// `--mesh-member`
    pub members: Vec<String>,
}

/// `[limits]`: each field is the flag of the same name.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_reservations: Option<usize>,
    pub max_reservations_per_ip: Option<usize>,
    pub reservation_duration: Option<u64>,
    pub max_circuits: Option<usize>,
    pub max_circuits_per_peer: Option<usize>,
    pub max_circuits_per_ip: Option<usize>,
    pub max_circuit_duration: Option<u64>,
    pub max_circuit_bytes: Option<u64>,
    pub max_pending_hop: Option<usize>,
    pub max_pending_stop: Option<usize>,
    pub control_timeout_ms: Option<u64>,
    /// `CAPACITY/REFILL_MS` or `off`, as the flag takes.
    pub reservation_peer_rate: Option<String>,
    pub reservation_ip_rate: Option<String>,
    pub circuit_peer_rate: Option<String>,
    pub circuit_ip_rate: Option<String>,
    pub max_rate_limit_entries: Option<usize>,
}

/// Reads and checks the file `--config` names.
pub fn load(path: &Path) -> Result<Options, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
    File::parse(&text)
        .and_then(|file| file.options())
        .map_err(|error| format!("config {}: {error}", path.display()))
}

impl File {
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|error| error.to_string())
    }

    /// The relay options this file selects, checked as the flags are.
    pub fn options(&self) -> Result<Options, String> {
        let mut options = Options {
            key_path: self.key.clone(),
            accepting: !self.paused,
            ..Options::default()
        };
        for bind in &self.quic {
            options.quic_binds.push(cli::socket("quic", bind.clone())?);
        }
        for bind in &self.tcp {
            options.tcp_binds.push(cli::socket("tcp", bind.clone())?);
        }
        if let Some(webtransport) = &self.webtransport {
            options.webtransport = true;
            options.webtransport_certificate = match (&webtransport.cert, &webtransport.key) {
                (Some(chain), Some(key)) => Some(CertificatePaths {
                    chain: chain.clone(),
                    key: key.clone(),
                }),
                (None, None) => None,
                _ => return Err("[webtransport] cert and key must be given together".into()),
            };
            if let Some(secs) = webtransport.reload_secs {
                options.webtransport_reload_interval = Duration::from_secs(secs);
            }
        }
        if let Some(hostname) = &self.hostname {
            validate_hostname(hostname)?;
            if !self.quic.is_empty() || !self.tcp.is_empty() {
                return Err(format!(
                    "hostname announces port {DEFAULT_PORT}; with quic or tcp binds, list announce addresses instead"
                ));
            }
            let mut derived = vec![
                format!("/dns/{hostname}/tcp/{DEFAULT_PORT}"),
                format!("/dns/{hostname}/udp/{DEFAULT_PORT}/quic-v1"),
            ];
            // Derived certificates need a /certhash, which the relay logs
            // as `webtransport=`; only a CA certificate is dialed by name.
            if options.webtransport_certificate.is_some() {
                derived.push(format!(
                    "/dns/{hostname}/udp/{DEFAULT_PORT}/quic-v1/webtransport"
                ));
            }
            for address in derived {
                options.announce_addrs.push(
                    address
                        .parse()
                        .map_err(|error| format!("invalid hostname {hostname:?}: {error}"))?,
                );
            }
        }
        for address in &self.announce {
            options.announce_addrs.push(
                address
                    .parse()
                    .map_err(|error| format!("invalid announce multiaddr {address:?}: {error}"))?,
            );
        }
        self.limits.apply(&mut options)?;
        if let Some(mesh) = &self.mesh {
            let key_path = mesh.key.clone().ok_or(
                "[mesh] needs key = \"PATH\": the backbone identity must persist across restarts",
            )?;
            let mut listen = Vec::new();
            for bind in &mesh.listen {
                listen.push(cli::socket("[mesh] listen", bind.clone())?);
            }
            let mut members = Vec::new();
            for member in &mesh.members {
                members.push(member.parse().map_err(|error| {
                    format!("invalid [mesh] members entry {member:?}: {error}")
                })?);
            }
            options.mesh = Some(MeshOptions {
                key_path,
                listen,
                members,
            });
        }
        cli::validate(&options)?;
        Ok(options)
    }
}

impl Limits {
    fn apply(&self, options: &mut Options) -> Result<(), String> {
        let config = &mut options.config;
        let set = |target: &mut usize, value: Option<usize>| {
            if let Some(value) = value {
                *target = value;
            }
        };
        set(&mut config.max_reservations, self.max_reservations);
        set(
            &mut config.max_reservations_per_ip,
            self.max_reservations_per_ip,
        );
        set(&mut config.max_circuits, self.max_circuits);
        set(
            &mut config.max_circuits_per_peer,
            self.max_circuits_per_peer,
        );
        set(&mut config.max_circuits_per_ip, self.max_circuits_per_ip);
        set(
            &mut config.max_pending_hop_requests_per_connection,
            self.max_pending_hop,
        );
        set(
            &mut config.max_pending_stop_requests_per_connection,
            self.max_pending_stop,
        );
        set(
            &mut config.max_rate_limit_entries,
            self.max_rate_limit_entries,
        );
        let set = |target: &mut u64, value: Option<u64>| {
            if let Some(value) = value {
                *target = value;
            }
        };
        set(
            &mut config.reservation_duration_secs,
            self.reservation_duration,
        );
        set(
            &mut config.max_circuit_duration_secs,
            self.max_circuit_duration,
        );
        set(&mut config.max_circuit_bytes, self.max_circuit_bytes);
        set(
            &mut config.control_stream_timeout_ms,
            self.control_timeout_ms,
        );
        for (target, value, field) in [
            (
                &mut config.reservation_rate_limit_per_peer,
                &self.reservation_peer_rate,
                "reservation_peer_rate",
            ),
            (
                &mut config.reservation_rate_limit_per_ip,
                &self.reservation_ip_rate,
                "reservation_ip_rate",
            ),
            (
                &mut config.circuit_rate_limit_per_peer,
                &self.circuit_peer_rate,
                "circuit_peer_rate",
            ),
            (
                &mut config.circuit_rate_limit_per_ip,
                &self.circuit_ip_rate,
                "circuit_ip_rate",
            ),
        ] {
            if let Some(value) = value {
                *target = cli::rate(field, value.clone())?;
            }
        }
        Ok(())
    }
}

/// Checks `hostname` is a DNS name, as `/dns/<hostname>` needs.
pub fn validate_hostname(hostname: &str) -> Result<(), String> {
    let valid = !hostname.is_empty()
        && hostname.len() <= 253
        && hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid hostname {hostname:?}: expected a DNS hostname"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMBER: &str = "/ip4/203.0.113.10/udp/19877/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";

    fn options(text: &str) -> Result<Options, String> {
        File::parse(text)?.options()
    }

    /// Each row is one flag set and the config that means the same; the
    /// test below checks every flag in `--help` has a row.
    fn table() -> Vec<(Vec<&'static str>, String)> {
        let identity = ["--key", "id.key"];
        let mut rows = vec![
            (
                vec!["--quic", "127.0.0.1:4101"],
                r#"quic = ["127.0.0.1:4101"]"#.to_owned(),
            ),
            (
                vec!["--tcp", "127.0.0.1:4201"],
                r#"tcp = ["127.0.0.1:4201"]"#.to_owned(),
            ),
            (identity.to_vec(), r#"key = "id.key""#.to_owned()),
            (
                vec!["--announce", "/ip4/203.0.113.4/tcp/4001"],
                r#"announce = ["/ip4/203.0.113.4/tcp/4001"]"#.to_owned(),
            ),
            (vec!["--paused"], "paused = true".to_owned()),
            (vec!["--webtransport"], "[webtransport]".to_owned()),
            (
                vec![
                    "--webtransport-cert",
                    "chain.pem",
                    "--webtransport-key",
                    "key.pem",
                ],
                "[webtransport]\ncert = \"chain.pem\"\nkey = \"key.pem\"".to_owned(),
            ),
            (
                vec!["--webtransport", "--webtransport-reload-secs", "5"],
                "[webtransport]\nreload_secs = 5".to_owned(),
            ),
            (
                vec![
                    "--key",
                    "id.key",
                    "--mesh-key",
                    "mesh.key",
                    "--mesh-listen",
                    "127.0.0.1:4301",
                    "--mesh-member",
                    MEMBER,
                ],
                format!(
                    "key = \"id.key\"\n[mesh]\nkey = \"mesh.key\"\nlisten = [\"127.0.0.1:4301\"]\nmembers = [\"{MEMBER}\"]"
                ),
            ),
        ];
        // `[limits]` names each flag without its dashes.
        for (flag, value) in [
            ("--max-reservations", "7"),
            ("--max-reservations-per-ip", "7"),
            ("--reservation-duration", "7"),
            ("--max-circuits", "7"),
            ("--max-circuits-per-peer", "7"),
            ("--max-circuits-per-ip", "7"),
            ("--max-circuit-duration", "7"),
            ("--max-circuit-bytes", "7"),
            ("--max-pending-hop", "7"),
            ("--max-pending-stop", "7"),
            ("--control-timeout-ms", "7"),
            ("--reservation-peer-rate", "3/250"),
            ("--reservation-ip-rate", "off"),
            ("--circuit-peer-rate", "3/250"),
            ("--circuit-ip-rate", "off"),
            ("--max-rate-limit-entries", "7"),
        ] {
            let field = flag.trim_start_matches('-').replace('-', "_");
            let toml_value = if value.parse::<u64>().is_ok() {
                value.to_owned()
            } else {
                format!("\"{value}\"")
            };
            rows.push((
                vec![flag, value],
                format!("[limits]\n{field} = {toml_value}"),
            ));
        }
        rows
    }

    #[test]
    fn every_flag_has_a_matching_field() {
        let rows = table();
        for (args, text) in &rows {
            let flags = cli::parse(args.iter().map(|arg| (*arg).to_owned())).unwrap();
            assert_eq!(flags, options(text).unwrap(), "{args:?} vs {text}");
        }
        let covered: Vec<&str> = rows.iter().flat_map(|(args, _)| args.clone()).collect();
        let usage = cli::usage();
        let options = usage
            .split("\n\nService management:")
            .next()
            .unwrap()
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|flag| flag.starts_with("--"));
        for flag in options {
            if !["--config", "-h,", "-V,"].contains(&flag) {
                assert!(covered.contains(&flag), "{flag} has no config field");
            }
        }
    }

    #[test]
    fn omitted_fields_keep_the_defaults() {
        assert_eq!(options("").unwrap(), Options::default());
    }

    #[test]
    fn rejects_unknown_fields() {
        for text in [
            "hostnme = \"relay.example.com\"",
            "[limits]\nmax_circuit = 1",
        ] {
            let error = options(text).unwrap_err();
            assert!(error.contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn hostname_announces_the_default_ports() {
        let announced = |text: &str| -> Vec<String> {
            options(text)
                .unwrap()
                .announce_addrs
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        let base = [
            "/dns/relay.example.com/tcp/19876",
            "/dns/relay.example.com/udp/19876/quic-v1",
        ];
        assert_eq!(announced("hostname = \"relay.example.com\""), base);
        // Derived certificates are dialed by /certhash, never by name.
        assert_eq!(
            announced("hostname = \"relay.example.com\"\n[webtransport]"),
            base
        );
        assert_eq!(
            announced(
                "hostname = \"relay.example.com\"\n[webtransport]\ncert = \"/c.pem\"\nkey = \"/k.pem\""
            ),
            [
                base[0],
                base[1],
                "/dns/relay.example.com/udp/19876/quic-v1/webtransport"
            ]
        );
    }

    #[test]
    fn hostname_rejects_custom_binds() {
        for bind in ["quic = [\"0.0.0.0:4101\"]", "tcp = [\"0.0.0.0:4101\"]"] {
            let error = options(&format!("hostname = \"relay.example.com\"\n{bind}")).unwrap_err();
            assert!(error.contains("list announce addresses"), "{error}");
        }
        let error = options("hostname = \"not a hostname\"").unwrap_err();
        assert!(error.contains("invalid hostname"), "{error}");
    }

    #[test]
    fn mesh_needs_a_persistent_backbone_key() {
        let error = options("key = \"id.key\"\n[mesh]").unwrap_err();
        assert!(error.contains("[mesh] needs key"), "{error}");
        let error = options("[mesh]\nkey = \"mesh.key\"").unwrap_err();
        assert!(error.contains("persistent identity"), "{error}");
    }

    #[test]
    fn a_certificate_needs_its_key() {
        let error = options("[webtransport]\ncert = \"/c.pem\"").unwrap_err();
        assert!(error.contains("must be given together"), "{error}");
    }
}
