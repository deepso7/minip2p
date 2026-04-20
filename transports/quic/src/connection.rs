use std::net::{SocketAddr, UdpSocket};

use minip2p_core::PeerId;
use minip2p_transport::{
    ConnectionEndpoint, ConnectionId, ConnectionState, TransportError, TransportEvent,
};

const SEND_BUF_SIZE: usize = 1350;

pub struct QuicConnection {
    id: ConnectionId,
    conn: quiche::Connection,
    peer_addr: SocketAddr,
    endpoint: ConnectionEndpoint,
    state: ConnectionState,
}

impl QuicConnection {
    pub fn new(
        id: ConnectionId,
        conn: quiche::Connection,
        peer_addr: SocketAddr,
        endpoint: ConnectionEndpoint,
    ) -> Self {
        Self {
            id,
            conn,
            peer_addr,
            endpoint,
            state: ConnectionState::Connecting,
        }
    }

    pub fn source_cid_bytes(&self) -> Vec<u8> {
        self.conn.source_id().as_ref().to_vec()
    }

    pub fn endpoint(&self) -> &ConnectionEndpoint {
        &self.endpoint
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.endpoint.set_peer_id(peer_id);
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    pub fn recv_packet(
        &mut self,
        buf: &mut [u8],
        from: SocketAddr,
        local: SocketAddr,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), TransportError> {
        let recv_info = quiche::RecvInfo { from, to: local };

        match self.conn.recv(buf, recv_info) {
            Ok(_) => {}
            Err(quiche::Error::Done) => {}
            Err(e) => {
                events.push(TransportEvent::Error {
                    id: self.id,
                    message: format!("recv error: {e}"),
                });
                return Ok(());
            }
        }

        if self.state == ConnectionState::Connecting && self.conn.is_established() {
            self.state = ConnectionState::Connected;
            self.flush(socket)?;

            events.push(TransportEvent::Connected {
                id: self.id,
                endpoint: self.endpoint.clone(),
            });
        } else {
            self.flush(socket)?;
        }

        Ok(())
    }

    pub fn send_data(&mut self, data: &[u8], socket: &UdpSocket) -> Result<(), TransportError> {
        let stream_id = if self.conn.is_server() { 1 } else { 0 };

        self.conn
            .stream_send(stream_id, data, false)
            .map_err(|e| TransportError::SendFailed {
                id: self.id,
                reason: format!("stream_send error: {e}"),
            })?;

        self.flush(socket)?;
        Ok(())
    }

    pub fn close(&mut self, socket: &UdpSocket) -> Result<(), TransportError> {
        self.conn
            .close(true, 0x00, b"bye")
            .map_err(|e| TransportError::CloseFailed {
                id: self.id,
                reason: format!("close error: {e}"),
            })?;

        self.state = ConnectionState::Closing;
        self.flush(socket)?;
        Ok(())
    }

    pub fn poll_streams(
        &mut self,
        events: &mut Vec<TransportEvent>,
        socket: &UdpSocket,
    ) -> Result<(), TransportError> {
        if !self.conn.is_established() {
            return Ok(());
        }

        let mut buf = [0u8; 65535];

        for stream_id in self.conn.readable() {
            while let Ok((read, fin)) = self.conn.stream_recv(stream_id, &mut buf) {
                if read > 0 {
                    events.push(TransportEvent::Received {
                        id: self.id,
                        data: buf[..read].to_vec(),
                    });
                }
                if fin {
                    break;
                }
            }
        }

        self.flush(socket)?;
        Ok(())
    }

    fn flush(&mut self, socket: &UdpSocket) -> Result<(), TransportError> {
        let mut out = [0u8; SEND_BUF_SIZE];
        loop {
            let (written, send_info) = match self.conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(TransportError::SendFailed {
                        id: self.id,
                        reason: format!("quiche send error: {e}"),
                    });
                }
            };

            socket.send_to(&out[..written], send_info.to).map_err(|e| {
                TransportError::SendFailed {
                    id: self.id,
                    reason: format!("udp send error: {e}"),
                }
            })?;
        }
        Ok(())
    }

    pub fn matches_peer(&self, addr: SocketAddr) -> bool {
        self.peer_addr == addr
    }
}
