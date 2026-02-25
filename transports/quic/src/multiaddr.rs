use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultiaddrError {
    #[error("empty multiaddr")]
    Empty,
    #[error("invalid multiaddr format")]
    InvalidFormat,
    #[error("missing udp component")]
    MissingUdp,
    #[error("missing quic component")]
    MissingQuicComponent,
    #[error("unsupported QUIC component '/quic' (draft-29); use '/quic-v1'")]
    UnsupportedDraft29,
    #[error("unsupported transport component '{0}'")]
    UnsupportedTransport(String),
    #[error("invalid ip address: {0}")]
    InvalidIp(String),
    #[error("invalid udp port: {0}")]
    InvalidPort(String),
}

pub fn parse_quic_v1_multiaddr(multiaddr: &str) -> Result<SocketAddr, MultiaddrError> {
    if multiaddr.is_empty() {
        return Err(MultiaddrError::Empty);
    }

    let parts: Vec<&str> = multiaddr
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if parts.len() != 5 {
        return Err(MultiaddrError::InvalidFormat);
    }

    let ip = match parts[0] {
        "ip4" | "ip6" => IpAddr::from_str(parts[1])
            .map_err(|_| MultiaddrError::InvalidIp(parts[1].to_owned()))?,
        _ => return Err(MultiaddrError::InvalidFormat),
    };

    if parts[2] != "udp" {
        return Err(MultiaddrError::MissingUdp);
    }

    let port = parts[3]
        .parse::<u16>()
        .map_err(|_| MultiaddrError::InvalidPort(parts[3].to_owned()))?;

    match parts[4] {
        "quic-v1" => Ok(SocketAddr::new(ip, port)),
        "quic" => Err(MultiaddrError::UnsupportedDraft29),
        other => Err(MultiaddrError::UnsupportedTransport(other.to_owned())),
    }
}

pub fn to_quic_v1_multiaddr(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => format!("/ip4/{ip}/udp/{}/quic-v1", addr.port()),
        IpAddr::V6(ip) => format!("/ip6/{ip}/udp/{}/quic-v1", addr.port()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quic_v1_address() {
        let parsed = parse_quic_v1_multiaddr("/ip4/127.0.0.1/udp/4001/quic-v1").expect("valid");
        assert_eq!(parsed.to_string(), "127.0.0.1:4001");
    }

    #[test]
    fn rejects_draft_29_component() {
        let err = parse_quic_v1_multiaddr("/ip4/127.0.0.1/udp/4001/quic")
            .expect_err("must reject draft-29");
        assert_eq!(err, MultiaddrError::UnsupportedDraft29);
    }
}
