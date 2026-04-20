use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::PeerAddr;

use crate::ConnectionId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    Connected {
        id: ConnectionId,
        addr: PeerAddr,
    },
    Received {
        id: ConnectionId,
        data: Vec<u8>,
    },
    Closed {
        id: ConnectionId,
    },
    Error {
        id: ConnectionId,
        message: String,
    },
    IncomingConnection {
        id: ConnectionId,
        addr: PeerAddr,
    },
    Listening {
        addr: minip2p_core::Multiaddr,
    },
}
