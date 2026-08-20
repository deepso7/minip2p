//! Helpers shared by the example binaries (`minip2p-peer`,
//! `minip2p-chat`): key persistence, NAT-event rendering, and address
//! shaping. Living in one place keeps the demos' security behavior and
//! CLI output from drifting apart.

use std::error::Error;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path as FsPath;
use std::process::Child;

use minip2p::{Ed25519Keypair, Multiaddr, NatEvent, Path, PeerAddr, PeerId, Protocol};

/// CLI parse error surfaced back to the examples' `main` so the binary
/// exits with a readable message rather than a panic.
#[derive(Clone, Debug)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

/// Returns the value following the flag at index `i`, or a "requires a
/// value" [`CliError`] naming `key`.
pub fn flag_value<'a>(args: &'a [String], i: usize, key: &str) -> Result<&'a String, CliError> {
    args.get(i + 1)
        .ok_or_else(|| CliError(format!("flag '{key}' requires a value")))
}

/// Rejects peer addresses the endpoint could never dial: everything the
/// examples connect to is QUIC, and catching the shape here turns an
/// asynchronous dial failure into an immediate input error.
pub fn require_quic_transport(what: &str, raw: &str, addr: &PeerAddr) -> Result<(), CliError> {
    if addr.transport().is_quic_transport() {
        Ok(())
    } else {
        Err(CliError(format!(
            "{what} must be on a /ip4|ip6|dns|dns4|dns6/<host>/udp/<port>/quic-v1 transport, got '{raw}'"
        )))
    }
}

/// Child process that is killed on drop so a panicking test assertion
/// doesn't leak a bound UDP socket.
pub struct KillOnDrop(pub Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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
        let raw = read_secret(path)?;
        let secret = decode_secret(raw.strip_suffix('\n').unwrap_or(&raw))
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

/// Opens and validates an existing key before reading at most one encoded
/// secret plus its optional newline. Non-blocking open avoids hanging on a
/// FIFO substituted for the requested path; metadata from the opened handle
/// prevents a pathname replacement from bypassing the checks.
#[cfg(unix)]
fn read_secret(path: &FsPath) -> Result<String, Box<dyn Error>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let path_metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("failed to inspect key file {}: {e}", path.display()))?;
    if !path_metadata.file_type().is_file() {
        return Err(format!("refusing key file {}: not a regular file", path.display()).into());
    }

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)
        .map_err(|e| format!("failed to open key file {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect key file {}: {e}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("refusing key file {}: not a regular file", path.display()).into());
    }

    let expected_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_uid {
        return Err(format!(
            "refusing key file {}: owned by uid {}, expected process uid {expected_uid}",
            path.display(),
            metadata.uid()
        )
        .into());
    }
    if metadata.mode() & 0o7777 != 0o600 {
        return Err(format!("refusing key file {}: mode must be 0600", path.display()).into());
    }

    let mut bytes = Vec::with_capacity(SECRET_KEY_LENGTH * 2 + 2);
    std::io::Read::by_ref(&mut file)
        .take((SECRET_KEY_LENGTH * 2 + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    if bytes.len() > SECRET_KEY_LENGTH * 2 + 1 {
        return Err(format!(
            "invalid key file {}: too large (expected 64 hex chars and optional newline)",
            path.display()
        )
        .into());
    }
    String::from_utf8(bytes).map_err(|e| format!("invalid key file {}: {e}", path.display()).into())
}

#[cfg(not(unix))]
fn read_secret(path: &FsPath) -> Result<String, Box<dyn Error>> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("failed to open key file {}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(SECRET_KEY_LENGTH * 2 + 2);
    std::io::Read::by_ref(&mut file)
        .take((SECRET_KEY_LENGTH * 2 + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read key file {}: {e}", path.display()))?;
    if bytes.len() > SECRET_KEY_LENGTH * 2 + 1 {
        return Err(format!(
            "invalid key file {}: too large (expected 64 hex chars and optional newline)",
            path.display()
        )
        .into());
    }
    String::from_utf8(bytes).map_err(|e| format!("invalid key file {}: {e}", path.display()).into())
}

/// Writes the raw secret into a file that is `0o600` from the moment it
/// exists: creating it world-readable and chmodding afterwards would leave
/// a window where a permissive umask exposes the key. `create_new` also
/// closes the check-then-write race — losing that race is an error, never
/// an overwrite.
#[cfg(unix)]
fn write_secret(path: &FsPath, secret: &[u8; SECRET_KEY_LENGTH]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create key directory {}: {e}", parent.display()))?;
    }

    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to create key file {}: {e}", path.display()))?;
    file.write_all(format!("{}\n", encode_hex(secret)).as_bytes())
        .map_err(|e| format!("failed to write key file {}: {e}", path.display()))?;
    Ok(())
}

/// Only unix permissions give the owner-only guarantee a raw secret needs;
/// refusing beats silently writing a key other principals may read.
#[cfg(not(unix))]
fn write_secret(path: &FsPath, _secret: &[u8; SECRET_KEY_LENGTH]) -> Result<(), Box<dyn Error>> {
    Err(format!(
        "refusing to create key file {}: persistent keys require unix file permissions \
         (owner-only access cannot be guaranteed on this platform)",
        path.display()
    )
    .into())
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
        NatEvent::InboundPathEstablished { peer, path } => {
            println!(
                "[{role}] nat-inbound-path-established peer={peer} path={}",
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "minip2p-example-common-{}-{}-{name}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn existing_key_must_be_owner_only() {
        let path = temp_path("permissive-key");
        fs::write(&path, format!("{}\n", "00".repeat(SECRET_KEY_LENGTH))).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = load_keypair(Some(&path), "test").unwrap_err().to_string();

        let _ = fs::remove_file(path);
        assert!(error.contains("0600"), "{error}");
    }

    #[test]
    fn existing_key_must_be_a_regular_file() {
        let path = temp_path("key-directory");
        fs::create_dir(&path).unwrap();

        let error = load_keypair(Some(&path), "test").unwrap_err().to_string();

        let _ = fs::remove_dir(path);
        assert!(error.contains("regular file"), "{error}");
    }

    #[test]
    fn existing_key_read_is_bounded() {
        let path = temp_path("oversized-key");
        fs::write(&path, "00".repeat(1024)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let error = load_keypair(Some(&path), "test").unwrap_err().to_string();

        let _ = fs::remove_file(path);
        assert!(error.contains("too large"), "{error}");
    }
}
