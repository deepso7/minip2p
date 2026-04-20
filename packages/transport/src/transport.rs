use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerAddr};

use crate::{ConnectionId, TransportError, TransportEvent};

pub trait Transport {
    fn dial(&mut self, id: ConnectionId, addr: &PeerAddr) -> Result<(), TransportError>;

    fn listen(&mut self, addr: &Multiaddr) -> Result<(), TransportError>;

    fn send(&mut self, id: ConnectionId, data: Vec<u8>) -> Result<(), TransportError>;

    fn close(&mut self, id: ConnectionId) -> Result<(), TransportError>;

    fn poll(&mut self) -> Result<Vec<TransportEvent>, TransportError>;
}
