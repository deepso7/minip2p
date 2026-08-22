use std::path::PathBuf;

use minip2p::{Multiaddr, RateLimit, RelayServerConfig};

#[derive(Debug)]
pub struct Options {
    /// Exact QUIC binds; empty selects automatic IPv4/IPv6 binding.
    pub quic_binds: Vec<String>,
    /// Exact TCP binds; empty selects automatic IPv4/IPv6 binding.
    pub tcp_binds: Vec<String>,
    pub key_path: Option<PathBuf>,
    pub announce_addrs: Vec<Multiaddr>,
    pub accepting: bool,
    pub config: RelayServerConfig,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        quic_binds: Vec::new(),
        tcp_binds: Vec::new(),
        key_path: None,
        announce_addrs: Vec::new(),
        accepting: true,
        config: RelayServerConfig::default(),
    };
    let mut args = args.into_iter().collect::<Vec<_>>().into_iter();
    while let Some(flag) = args.next() {
        let value = |args: &mut std::vec::IntoIter<String>| next_value(&flag, args);
        match flag.as_str() {
            "--help" | "-h" => return Err(usage().into()),
            "--quic" => options.quic_binds.push(value(&mut args)?),
            "--tcp" => options.tcp_binds.push(value(&mut args)?),
            "--key" => options.key_path = Some(value(&mut args)?.into()),
            "--announce" => options.announce_addrs.push(
                value(&mut args)?
                    .parse()
                    .map_err(|error| format!("invalid --announce multiaddr: {error}"))?,
            ),
            "--paused" => options.accepting = false,
            "--max-reservations" => {
                options.config.max_reservations = number(&flag, value(&mut args)?)?
            }
            "--reservation-duration" => {
                options.config.reservation_duration_secs = number(&flag, value(&mut args)?)?
            }
            "--max-circuits" => options.config.max_circuits = number(&flag, value(&mut args)?)?,
            "--max-circuits-per-peer" => {
                options.config.max_circuits_per_peer = number(&flag, value(&mut args)?)?
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
            _ => return Err(format!("unknown option {flag}\n\n{}", usage())),
        }
    }
    if options.quic_binds.len() > 2 {
        return Err("--quic accepts at most one IPv4 and one IPv6 address".into());
    }
    options
        .config
        .validate()
        .map_err(|error| error.to_string())?;
    Ok(options)
}

fn next_value(flag: &str, args: &mut std::vec::IntoIter<String>) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value\n\n{}", usage()))
}

fn number<T: core::str::FromStr>(flag: &str, value: String) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} requires a non-negative integer, got {value:?}"))
}

fn rate(flag: &str, value: String) -> Result<Option<RateLimit>, String> {
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
    "usage: minip2p-relay-server [options]\n\nDefaults try QUIC and TCP on IPv4 and IPv6 port 4001, falling back to the available family.\n\n--quic ADDR                    exact QUIC socket bind (repeatable; replaces automatic binds)\n--tcp ADDR                     exact TCP socket bind (repeatable; replaces automatic binds)\n--key PATH                     load/create persistent Ed25519 identity\n--announce MULTIADDR           explicit public address (repeatable)\n--paused                       start with new admissions paused\n--max-reservations N           reservation capacity\n--reservation-duration SECS    reservation lifetime\n--max-circuits N               circuit capacity\n--max-circuits-per-peer N      per-endpoint circuit capacity\n--max-circuit-duration SECS    circuit lifetime (0 = unlimited)\n--max-circuit-bytes BYTES      per-direction bytes (0 = unlimited)\n--max-pending-hop N            pending HOP controls per connection\n--max-pending-stop N           pending STOP controls per connection\n--control-timeout-ms MS        end-to-end control timeout\n--reservation-peer-rate R      CAPACITY/REFILL_MS or off\n--reservation-ip-rate R        CAPACITY/REFILL_MS or off\n--circuit-peer-rate R          CAPACITY/REFILL_MS or off\n--circuit-ip-rate R            CAPACITY/REFILL_MS or off\n-h, --help                     show this help"
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
        assert_eq!(options.config, RelayServerConfig::default());
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

        assert_eq!(options.quic_binds, ["127.0.0.1:4101", "[::1]:4101"]);
        assert_eq!(options.tcp_binds, ["127.0.0.1:4201", "[::1]:4201"]);
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
            "--max-circuits".into(),
            "7".into(),
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
        assert_eq!(options.config.max_circuits, 7);
        assert_eq!(
            options.config.reservation_rate_limit_per_peer,
            Some(RateLimit {
                capacity: 3,
                refill_interval_ms: 250,
            })
        );
        assert_eq!(options.config.circuit_rate_limit_per_ip, None);
    }
}
