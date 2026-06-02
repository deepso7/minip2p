//! Runtime-only helpers for the demo CLI.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;

use minip2p_core::{Multiaddr, Protocol};
use minip2p_identity::{ED25519_SECRET_KEY_LENGTH, Ed25519Keypair};

use crate::cli::RunOptions;

const DEFAULT_BIND: &str = "127.0.0.1:0";

/// Loads a persistent key from `--key`, or generates and writes one when missing.
pub fn load_keypair(options: &RunOptions, role: &str) -> Result<Ed25519Keypair, Box<dyn Error>> {
    let Some(path) = &options.key_path else {
        let keypair = Ed25519Keypair::generate();
        println!("[{role}] peer={} identity=ephemeral", keypair.peer_id());
        return Ok(keypair);
    };

    if path.exists() {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
        let secret = decode_secret(raw.trim())
            .map_err(|e| format!("invalid key file {}: {e}", path.display()))?;
        let keypair = Ed25519Keypair::from_secret_key_bytes(secret);
        println!(
            "[{role}] peer={} identity={} persisted=loaded",
            keypair.peer_id(),
            path.display()
        );
        return Ok(keypair);
    }

    let keypair = Ed25519Keypair::generate();
    write_secret(path, &keypair.secret_key_bytes())?;
    println!(
        "[{role}] peer={} identity={} persisted=created",
        keypair.peer_id(),
        path.display()
    );
    Ok(keypair)
}

/// Returns the UDP bind address for the configured listen multiaddr.
pub fn bind_addr(options: &RunOptions) -> Result<String, Box<dyn Error>> {
    match &options.listen_addr {
        Some(addr) => multiaddr_to_socket_addr(addr).map(|addr| addr.to_string()),
        None => Ok(DEFAULT_BIND.into()),
    }
}

/// Returns global IPv6 interface addresses using the UDP port from `bound_transport`.
///
/// This is std-only CLI glue for DCUtR experiments. Core remains transport and
/// platform agnostic; the example merely turns local interface information into
/// extra direct candidates when the user binds an IPv6 socket.
pub fn local_global_ipv6_quic_addrs(bound_transport: &Multiaddr) -> Vec<Multiaddr> {
    if !matches!(bound_transport.protocols().first(), Some(Protocol::Ip6(_))) {
        return Vec::new();
    }

    let Some(port) = udp_port(bound_transport) else {
        return Vec::new();
    };

    local_global_ipv6_addrs()
        .into_iter()
        .map(|ip| ipv6_quic_addr(ip, port))
        .collect()
}

fn ipv6_quic_addr(ip: Ipv6Addr, port: u16) -> Multiaddr {
    Multiaddr::from_protocols(vec![
        Protocol::Ip6(ip.octets()),
        Protocol::Udp(port),
        Protocol::QuicV1,
    ])
}

fn udp_port(addr: &Multiaddr) -> Option<u16> {
    addr.protocols().iter().find_map(|protocol| match protocol {
        Protocol::Udp(port) => Some(*port),
        _ => None,
    })
}

#[cfg(unix)]
fn local_global_ipv6_addrs() -> Vec<Ipv6Addr> {
    let mut head = std::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 || head.is_null() {
        return Vec::new();
    }

    struct IfAddrsGuard(*mut libc::ifaddrs);
    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = IfAddrsGuard(head);

    let mut addrs = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let ifaddr = unsafe { &*cursor };
        if !ifaddr.ifa_addr.is_null() {
            let family = unsafe { (*ifaddr.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET6 {
                let sockaddr = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr);
                if is_global_unicast_ipv6(&ip) && !addrs.iter().any(|existing| existing == &ip) {
                    addrs.push(ip);
                }
            }
        }
        cursor = ifaddr.ifa_next;
    }

    addrs
}

#[cfg(not(unix))]
fn local_global_ipv6_addrs() -> Vec<Ipv6Addr> {
    Vec::new()
}

fn is_global_unicast_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    let first = segments[0];

    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && (first & 0xffc0) != 0xfe80
        && (first & 0xfe00) != 0xfc00
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn write_secret(
    path: &Path,
    secret: &[u8; ED25519_SECRET_KEY_LENGTH],
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create key directory {}: {e}", parent.display()))?;
    }

    let data = format!("{}\n", encode_hex(secret));
    fs::write(path, data)
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .map_err(|e| format!("failed to chmod key file {}: {e}", path.display()))?;
    }

    Ok(())
}

fn multiaddr_to_socket_addr(addr: &Multiaddr) -> Result<SocketAddr, Box<dyn Error>> {
    let protocols = addr.protocols();
    if protocols.len() != 3 || !addr.is_quic_transport() {
        return Err(
            format!("--listen must be /ip4|ip6/<addr>/udp/<port>/quic-v1, got {addr}").into(),
        );
    }

    let ip = match &protocols[0] {
        Protocol::Ip4(bytes) => IpAddr::from(*bytes),
        Protocol::Ip6(bytes) => IpAddr::from(*bytes),
        _ => return Err(format!("--listen requires /ip4 or /ip6 host, got {addr}").into()),
    };
    let port = match &protocols[1] {
        Protocol::Udp(port) => *port,
        _ => unreachable!("is_quic_transport already checked udp"),
    };
    Ok(SocketAddr::new(ip, port))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_secret(input: &str) -> Result<[u8; ED25519_SECRET_KEY_LENGTH], String> {
    if input.len() != ED25519_SECRET_KEY_LENGTH * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            ED25519_SECRET_KEY_LENGTH * 2,
            input.len()
        ));
    }

    let mut out = [0u8; ED25519_SECRET_KEY_LENGTH];
    let bytes = input.as_bytes();
    for idx in 0..ED25519_SECRET_KEY_LENGTH {
        let hi = hex_value(bytes[idx * 2])?;
        let lo = hex_value(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("non-hex byte 0x{byte:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::*;

    #[test]
    fn local_ipv6_candidates_use_bound_udp_port() {
        let bound = Multiaddr::from_str("/ip6/::/udp/4242/quic-v1").unwrap();
        let candidate = ipv6_quic_addr(Ipv6Addr::LOCALHOST, udp_port(&bound).unwrap());

        assert_eq!(candidate.to_string(), "/ip6/::1/udp/4242/quic-v1");
    }

    #[test]
    fn global_ipv6_filter_skips_non_public_ranges() {
        assert!(!is_global_unicast_ipv6(&Ipv6Addr::UNSPECIFIED));
        assert!(!is_global_unicast_ipv6(&Ipv6Addr::LOCALHOST));
        assert!(!is_global_unicast_ipv6(
            &Ipv6Addr::from_str("fe80::1").unwrap()
        ));
        assert!(!is_global_unicast_ipv6(
            &Ipv6Addr::from_str("fd00::1").unwrap()
        ));
        assert!(!is_global_unicast_ipv6(
            &Ipv6Addr::from_str("ff02::1").unwrap()
        ));
        assert!(!is_global_unicast_ipv6(
            &Ipv6Addr::from_str("2001:db8::1").unwrap()
        ));
        assert!(is_global_unicast_ipv6(
            &Ipv6Addr::from_str("2001:4860:4860::8888").unwrap()
        ));
    }
}
