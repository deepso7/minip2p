use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr};

use crate::ConnectionId;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportAction {
    Dial { id: ConnectionId, addr: PeerAddr },
    Listen { addr: Multiaddr },
    Send { id: ConnectionId, data: Vec<u8> },
    Close { id: ConnectionId },
}
