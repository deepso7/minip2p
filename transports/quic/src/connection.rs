use std::net::{SocketAddr, UdpSocket};

use minip2p_transport::{ConnectionId, ConnectionState, TransportEvent};
use quiche::ConnectionId as QuicConnectionId;

const SEND_BUF_SIZE: usize = 1350;

pub struct QuicConnection {
    id: ConnectionId,
    conn: quiche::Connection,
    peer_addr: SocketAddr,
    state: ConnectionState,
}

impl QuicConnection {
    pub fn new(id: ConnectionId, conn: quiche::Connection, peer_addr: SocketAddr) -> Self {
        Self {
            id,
            conn,
            peer_addr,
            state: ConnectionState::Connecting,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn matches_dcid(&self, dcid: &QuicConnectionId) -> bool {
        let source_id = self.conn.source_id();
        &source_id == dcid
    }

    pub fn matches_peer(&self, addr: SocketAddr) -> bool {
        self.peer_addr == addr
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    pub fn recv_packet(
        &mut self,
        buf: &[u8],
        from: SocketAddr,
        local: SocketAddr,
        socket: &UdpSocket,
        events: &mut Vec<TransportEvent>,
    ) -> Result<(), minip2p_transport::TransportError> {
        let recv_info = quiche::RecvInfo { from, to: local };
        let mut pkt = buf.to_vec();

        match self.conn.recv(&mut pkt, recv_info) {
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

            let peer_addr = build_peer_addr_event(self.peer_addr);
            events.push(TransportEvent::Connected {
                id: self.id,
                addr: peer_addr,
            });
        } else {
            self.flush(socket)?;
        }

        Ok(())
    }

    pub fn send_data(
        &mut self,
        data: &[u8],
        socket: &UdpSocket,
    ) -> Result<(), minip2p_transport::TransportError> {
        let stream_id = if self.conn.is_server() { 1 } else { 0 };

        self.conn
            .stream_send(stream_id, data, false)
            .map_err(|e| minip2p_transport::TransportError::SendFailed {
                id: self.id,
                reason: format!("stream_send error: {e}"),
            })?;

        self.flush(socket)?;
        Ok(())
    }

    pub fn close(
        &mut self,
        socket: &UdpSocket,
    ) -> Result<(), minip2p_transport::TransportError> {
        self.conn
            .close(true, 0x00, b"bye")
            .map_err(|e| minip2p_transport::TransportError::CloseFailed {
                id: self.id,
                reason: format!("close error: {e}"),
            })?;

        self.state = ConnectionState::Closing;
        self.flush(socket)?;
        Ok(())
    }

    pub fn poll_streams(
        &mut self,
        id: ConnectionId,
        events: &mut Vec<TransportEvent>,
        socket: &UdpSocket,
    ) -> Result<(), minip2p_transport::TransportError> {
        if !self.conn.is_established() {
            return Ok(());
        }

        let mut buf = [0u8; 65535];

        for stream_id in self.conn.readable() {
            while let Ok((read, fin)) = self.conn.stream_recv(stream_id, &mut buf) {
                if read > 0 {
                    events.push(TransportEvent::Received {
                        id,
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

    fn flush(&mut self, socket: &UdpSocket) -> Result<(), minip2p_transport::TransportError> {
        let mut out = [0u8; SEND_BUF_SIZE];
        loop {
            let (written, send_info) = match self.conn.send(&mut out) {
                Ok(v) => v,
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    return Err(minip2p_transport::TransportError::SendFailed {
                        id: self.id,
                        reason: format!("quiche send error: {e}"),
                    });
                }
            };

            socket
                .send_to(&out[..written], send_info.to)
                .map_err(|e| minip2p_transport::TransportError::SendFailed {
                    id: self.id,
                    reason: format!("udp send error: {e}"),
                })?;
        }
        Ok(())
    }
}

fn build_peer_addr_event(sock_addr: SocketAddr) -> minip2p_core::PeerAddr {
    let transport = match sock_addr {
        SocketAddr::V4(v4) => minip2p_core::Multiaddr::from_protocols(vec![
            minip2p_core::Protocol::Ip4(v4.ip().octets()),
            minip2p_core::Protocol::Udp(v4.port()),
            minip2p_core::Protocol::QuicV1,
        ]),
        SocketAddr::V6(v6) => minip2p_core::Multiaddr::from_protocols(vec![
            minip2p_core::Protocol::Ip6(v6.ip().octets()),
            minip2p_core::Protocol::Udp(v6.port()),
            minip2p_core::Protocol::QuicV1,
        ]),
    };

    let peer_id = minip2p_identity::PeerId::from_bytes(&[0x00, 0x04, 0x01, 0x02, 0x03, 0x04])
        .expect("hardcoded dummy peer id must parse");

    minip2p_core::PeerAddr::new(transport, peer_id)
        .expect("hardcoded transport + peer_id must be valid")
}
