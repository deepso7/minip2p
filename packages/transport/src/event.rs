use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId};

use crate::{ConnectionEndpoint, ConnectionId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportEvent {
    Connected {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
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
        endpoint: ConnectionEndpoint,
    },
    PeerIdentityVerified {
        id: ConnectionId,
        endpoint: ConnectionEndpoint,
        previous_peer_id: Option<PeerId>,
    },
    Listening {
        addr: Multiaddr,
    },
}
