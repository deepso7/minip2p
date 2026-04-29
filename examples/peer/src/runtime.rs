//! Runtime-only helpers for the demo CLI.

use std::error::Error;
use std::fs;
use std::net::{IpAddr, SocketAddr};
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
