//! Helpers shared by the example binaries (`minip2p-peer`,
//! `minip2p-chat`): key persistence, NAT-event rendering, and address
//! shaping. Living in one place keeps the demos' security behavior and
//! CLI output from drifting apart.

use std::error::Error;
use std::fs;
use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path as FsPath;

use minip2p::{Ed25519Keypair, Multiaddr, NatEvent, Path, PeerAddr, PeerId, Protocol};

/// Raw Ed25519 secret length; `Ed25519Keypair::from_secret_key_bytes`
/// enforces it at compile time via the array parameter.
const SECRET_KEY_LENGTH: usize = 32;

/// Loads a persistent key from `key_path`, or generates one (writing it
/// back when a path was given). Prints the identity line the examples'
/// machine-readable output starts with.
pub fn load_keypair(
    key_path: Option<&FsPath>,
    role: &str,
) -> Result<Ed25519Keypair, Box<dyn Error>> {
    let Some(path) = key_path else {
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

/// Writes the raw secret into a file that is `0o600` from the moment it
/// exists: creating it world-readable and chmodding afterwards would leave
/// a window where a permissive umask exposes the key. `create_new` also
/// closes the check-then-write race — losing that race is an error, never
/// an overwrite.
fn write_secret(path: &FsPath, secret: &[u8; SECRET_KEY_LENGTH]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create key directory {}: {e}", parent.display()))?;
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("failed to create key file {}: {e}", path.display()))?;
    file.write_all(format!("{}\n", encode_hex(secret)).as_bytes())
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;
    Ok(())
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

fn decode_secret(input: &str) -> Result<[u8; SECRET_KEY_LENGTH], String> {
    if input.len() != SECRET_KEY_LENGTH * 2 {
        return Err(format!(
            "expected {} hex chars, got {}",
            SECRET_KEY_LENGTH * 2,
            input.len()
        ));
    }

    let mut out = [0u8; SECRET_KEY_LENGTH];
    let bytes = input.as_bytes();
    for idx in 0..SECRET_KEY_LENGTH {
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

/// Short stable name for a [`Path`] variant, used in CLI event lines.
pub fn path_name(path: &Path) -> &'static str {
    match path {
        Path::DirectDialed => "direct-dialed",
        Path::DirectPunched => "direct-punched",
        Path::Relayed { .. } => "relayed",
    }
}

/// Prints a [`NatEvent`] in the examples' one-event-per-line format.
pub fn print_nat_event(role: &str, event: &NatEvent) {
    match event {
        NatEvent::ReachabilityChanged {
            old,
            new,
            confirmed_addrs,
        } => {
            let addrs = format_addrs(confirmed_addrs);
            println!("[{role}] nat-reachability old={old:?} new={new:?} confirmed=[{addrs}]");
        }
        NatEvent::PublicAddressesChanged { addrs } => {
            println!("[{role}] nat-public-addrs addrs=[{}]", format_addrs(addrs));
        }
        NatEvent::RelayReserved {
            relay,
            expires_unix_secs,
            ..
        } => {
            let expires = expires_unix_secs
                .map(|secs| secs.to_string())
                .unwrap_or_else(|| "?".into());
            println!("[{role}] nat-relay-reserved relay={relay} expires-unix={expires}");
        }
        NatEvent::RelayReservationLost { relay } => {
            println!("[{role}] nat-relay-reservation-lost relay={relay}");
        }
        NatEvent::PathEstablished { peer, path, .. } => {
            println!(
                "[{role}] nat-path-established peer={peer} path={}",
                path_name(path)
            );
        }
        NatEvent::PathUpgraded { peer, from, to, .. } => {
            println!(
                "[{role}] nat-path-upgraded peer={peer} from={} to={}",
                path_name(from),
                path_name(to)
            );
        }
        NatEvent::HolePunchFailed {
            attempt, reason, ..
        } => {
            println!("[{role}] nat-holepunch-failed attempt={attempt} reason={reason}");
        }
        NatEvent::FellBackToRelay { peer, .. } => {
            println!("[{role}] nat-fell-back-to-relay peer={peer}");
        }
        NatEvent::ConnectFailed { peer, error, .. } => {
            println!("[{role}] nat-connect-failed peer={peer} error={error}");
        }
        NatEvent::InboundRelayCircuit {
            peer,
            relay,
            stream_id,
            pending_data,
            remote_write_closed,
        } => {
            println!(
                "[{role}] nat-inbound-circuit peer={peer} relay={relay} stream={stream_id} \
                 pending-bytes={} remote-write-closed={remote_write_closed}",
                pending_data.len()
            );
        }
        NatEvent::InboundDirectUpgrade { peer } => {
            println!("[{role}] nat-inbound-direct-upgrade peer={peer}");
        }
    }
}

fn format_addrs(addrs: &[Multiaddr]) -> String {
    addrs
        .iter()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Rewrites a wildcard-bound peer-addr (`0.0.0.0` / `::`) to loopback so
/// the printed `bound=` line is directly dialable on the same host.
pub fn local_dialable_peer_addr(peer_addr: &PeerAddr) -> PeerAddr {
    let protocols = peer_addr.transport().protocols();
    let Some(first) = protocols.first() else {
        return peer_addr.clone();
    };

    let replacement = match first {
        Protocol::Ip4(bytes) if *bytes == [0, 0, 0, 0] => {
            Some(Protocol::Ip4(Ipv4Addr::LOCALHOST.octets()))
        }
        Protocol::Ip6(bytes) if *bytes == [0; 16] => {
            Some(Protocol::Ip6(Ipv6Addr::LOCALHOST.octets()))
        }
        _ => None,
    };

    let Some(replacement) = replacement else {
        return peer_addr.clone();
    };

    let mut rewritten = protocols.to_vec();
    rewritten[0] = replacement;
    PeerAddr::new(
        Multiaddr::from_protocols(rewritten),
        peer_addr.peer_id().clone(),
    )
    .unwrap_or_else(|_| peer_addr.clone())
}

/// The circuit address a dialer pastes to reach `us` through `relay`.
pub fn circuit_addr(relay: &PeerAddr, us: &PeerId) -> Multiaddr {
    let mut protocols = relay.transport().protocols().to_vec();
    protocols.push(Protocol::P2p(relay.peer_id().clone()));
    protocols.push(Protocol::P2pCircuit);
    protocols.push(Protocol::P2p(us.clone()));
    Multiaddr::from_protocols(protocols)
}
