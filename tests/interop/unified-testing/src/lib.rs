//! Pieces shared by the interop test apps in `src/main.rs` (transport) and
//! `src/bin/*.rs` (one binary per suite).

use std::error::Error;
use std::net::{IpAddr, UdpSocket};

pub mod redis;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// This container's address on the network that reaches `redis_addr`.
///
/// Every harness puts Redis on the network the peers share, so the interface
/// that routes to it is the one to bind and advertise. Connecting a UDP
/// socket sends nothing; it only makes the kernel pick that interface.
pub fn local_ip_towards(redis_addr: &str) -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(redis_addr)?;
    Ok(socket.local_addr()?.ip())
}
