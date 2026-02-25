mod auth;
pub mod multiaddr;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use auth::{AuthError, generate_certificate, verify_peer_certificate};
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use minip2p_identity::{Keypair, PeerId};
use rand_core::{OsRng, RngCore};
use thiserror::Error;

const LIBP2P_ALPN: &[u8] = b"libp2p";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Client,
    Server,
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub max_idle_timeout_ms: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub disable_active_migration: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: 10_000,
            initial_max_data: 15_000_000,
            initial_max_stream_data: 10_000_000,
            initial_max_streams_bidi: 256,
            initial_max_streams_uni: 256,
            disable_active_migration: true,
        }
    }
}

#[derive(Debug)]
enum AuthState {
    Pending,
    Verified(PeerId),
    Failed,
}

pub struct QuicConnection {
    conn: quiche::Connection,
    expected_peer: Option<PeerId>,
    auth_state: AuthState,
}

#[derive(Clone, Copy, Debug)]
pub struct Transmit {
    pub len: usize,
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub at: Instant,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Quiche(#[from] quiche::Error),
    #[error(transparent)]
    Tls(#[from] boring::error::ErrorStack),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("authentication has not completed")]
    NotAuthenticated,
    #[error("ALPN mismatch: expected 'libp2p', got '{0}'")]
    AlpnMismatch(String),
}

impl QuicConnection {
    pub fn connect(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        host_keypair: &Keypair,
        expected_peer: Option<PeerId>,
        transport_config: TransportConfig,
    ) -> Result<Self, Error> {
        let mut config = build_quiche_config(Role::Client, host_keypair, &transport_config)?;
        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        OsRng.fill_bytes(&mut scid_bytes);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let conn = quiche::connect(None, &scid, local_addr, peer_addr, &mut config)?;

        Ok(Self {
            conn,
            expected_peer,
            auth_state: AuthState::Pending,
        })
    }

    pub fn accept(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        host_keypair: &Keypair,
        transport_config: TransportConfig,
    ) -> Result<Self, Error> {
        let mut config = build_quiche_config(Role::Server, host_keypair, &transport_config)?;
        let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        OsRng.fill_bytes(&mut scid_bytes);
        let scid = quiche::ConnectionId::from_ref(&scid_bytes);

        let conn = quiche::accept(&scid, None, local_addr, peer_addr, &mut config)?;

        Ok(Self {
            conn,
            expected_peer: None,
            auth_state: AuthState::Pending,
        })
    }

    pub fn recv(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<usize, Error> {
        let read = self.conn.recv(packet, quiche::RecvInfo { from, to })?;
        self.maybe_authenticate()?;
        Ok(read)
    }

    pub fn poll_transmit(&mut self, out: &mut [u8]) -> Result<Option<Transmit>, Error> {
        match self.conn.send(out) {
            Ok((len, info)) => Ok(Some(Transmit {
                len,
                from: info.from,
                to: info.to,
                at: info.at,
            })),
            Err(quiche::Error::Done) => Ok(None),
            Err(err) => Err(Error::Quiche(err)),
        }
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.conn.timeout()
    }

    pub fn on_timeout(&mut self) {
        self.conn.on_timeout();
    }

    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<(), Error> {
        self.conn.close(app, err, reason)?;
        Ok(())
    }

    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.auth_state, AuthState::Verified(_))
    }

    pub fn authenticated_peer(&self) -> Option<&PeerId> {
        match &self.auth_state {
            AuthState::Verified(peer_id) => Some(peer_id),
            AuthState::Pending | AuthState::Failed => None,
        }
    }

    pub fn stream_send(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        self.ensure_authenticated()?;
        Ok(self.conn.stream_send(stream_id, data, fin)?)
    }

    pub fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool), Error> {
        self.ensure_authenticated()?;
        Ok(self.conn.stream_recv(stream_id, out)?)
    }

    pub fn readable_streams(&self) -> Vec<u64> {
        if !self.is_authenticated() {
            return Vec::new();
        }

        self.conn.readable().collect()
    }

    fn ensure_authenticated(&self) -> Result<(), Error> {
        if !self.is_authenticated() {
            return Err(Error::NotAuthenticated);
        }
        Ok(())
    }

    fn maybe_authenticate(&mut self) -> Result<(), Error> {
        match self.auth_state {
            AuthState::Verified(_) => return Ok(()),
            AuthState::Failed => return Err(Error::NotAuthenticated),
            AuthState::Pending => {}
        }

        if !self.conn.is_established() {
            return Ok(());
        }

        if self.conn.application_proto() != LIBP2P_ALPN {
            return self.fail_authentication(Error::AlpnMismatch(
                String::from_utf8_lossy(self.conn.application_proto()).into_owned(),
            ));
        }

        let peer_id = verify_peer_certificate(
            self.conn.peer_cert_chain(),
            self.conn.peer_cert(),
            self.expected_peer.as_ref(),
        )?;

        self.auth_state = AuthState::Verified(peer_id);
        Ok(())
    }

    fn fail_authentication(&mut self, err: Error) -> Result<(), Error> {
        self.auth_state = AuthState::Failed;
        let _ = self.conn.close(true, 0x12, b"peer authentication failed");
        Err(err)
    }
}

fn build_quiche_config(
    role: Role,
    host_keypair: &Keypair,
    transport_config: &TransportConfig,
) -> Result<quiche::Config, Error> {
    let generated = generate_certificate(host_keypair)?;

    let cert = boring::x509::X509::from_pem(generated.certificate_pem.as_bytes())?;
    let private_key =
        boring::pkey::PKey::private_key_from_pem(generated.private_key_pem.as_bytes())?;

    let mut tls_ctx_builder = SslContextBuilder::new(SslMethod::tls())?;
    tls_ctx_builder.set_certificate(&cert)?;
    tls_ctx_builder.set_private_key(&private_key)?;
    tls_ctx_builder.check_private_key()?;

    let verify_mode = match role {
        Role::Client => SslVerifyMode::PEER,
        Role::Server => SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    };

    tls_ctx_builder.set_verify_callback(verify_mode, |_preverified, _ctx| true);

    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls_ctx_builder)?;

    config.set_application_protos(&[LIBP2P_ALPN])?;
    config.set_max_idle_timeout(transport_config.max_idle_timeout_ms);
    config.set_initial_max_data(transport_config.initial_max_data);
    config.set_initial_max_stream_data_bidi_local(transport_config.initial_max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(transport_config.initial_max_stream_data);
    config.set_initial_max_stream_data_uni(transport_config.initial_max_stream_data);
    config.set_initial_max_streams_bidi(transport_config.initial_max_streams_bidi);
    config.set_initial_max_streams_uni(transport_config.initial_max_streams_uni);
    config.set_disable_active_migration(transport_config.disable_active_migration);

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive_handshake(
        client: &mut QuicConnection,
        server: &mut QuicConnection,
    ) -> Result<(), Error> {
        let mut c_out = [0u8; 1500];
        let mut s_out = [0u8; 1500];

        for _ in 0..2_000 {
            let mut progressed = false;

            while let Some(tx) = client.poll_transmit(&mut c_out)? {
                let mut packet = c_out[..tx.len].to_vec();
                server.recv(&mut packet, tx.from, tx.to)?;
                progressed = true;
            }

            while let Some(tx) = server.poll_transmit(&mut s_out)? {
                let mut packet = s_out[..tx.len].to_vec();
                client.recv(&mut packet, tx.from, tx.to)?;
                progressed = true;
            }

            if client.is_authenticated() && server.is_authenticated() {
                return Ok(());
            }

            if !progressed {
                if matches!(client.timeout(), Some(d) if d.is_zero()) {
                    client.on_timeout();
                    progressed = true;
                }

                if matches!(server.timeout(), Some(d) if d.is_zero()) {
                    server.on_timeout();
                    progressed = true;
                }
            }

            if !progressed {
                break;
            }
        }

        Err(Error::NotAuthenticated)
    }

    #[test]
    fn authenticates_client_and_server() {
        let client_identity = Keypair::from_ed25519_secret([1u8; 32]);
        let server_identity = Keypair::from_ed25519_secret([2u8; 32]);
        let expected_server = PeerId::from_public_key(&server_identity.public());

        let mut client = QuicConnection::connect(
            "127.0.0.1:40001".parse().expect("valid"),
            "127.0.0.1:40002".parse().expect("valid"),
            &client_identity,
            Some(expected_server),
            TransportConfig::default(),
        )
        .expect("connect");

        let mut server = QuicConnection::accept(
            "127.0.0.1:40002".parse().expect("valid"),
            "127.0.0.1:40001".parse().expect("valid"),
            &server_identity,
            TransportConfig::default(),
        )
        .expect("accept");

        drive_handshake(&mut client, &mut server).expect("handshake should complete");
        assert!(client.is_authenticated());
        assert!(server.is_authenticated());
    }

    #[test]
    fn fails_when_expected_peer_does_not_match() {
        let client_identity = Keypair::from_ed25519_secret([3u8; 32]);
        let server_identity = Keypair::from_ed25519_secret([4u8; 32]);
        let wrong_peer = PeerId::from_public_key(&Keypair::from_ed25519_secret([5u8; 32]).public());

        let mut client = QuicConnection::connect(
            "127.0.0.1:41001".parse().expect("valid"),
            "127.0.0.1:41002".parse().expect("valid"),
            &client_identity,
            Some(wrong_peer),
            TransportConfig::default(),
        )
        .expect("connect");

        let mut server = QuicConnection::accept(
            "127.0.0.1:41002".parse().expect("valid"),
            "127.0.0.1:41001".parse().expect("valid"),
            &server_identity,
            TransportConfig::default(),
        )
        .expect("accept");

        let err = drive_handshake(&mut client, &mut server).expect_err("must fail");
        assert!(matches!(
            err,
            Error::Auth(AuthError::PeerIdMismatch { .. }) | Error::NotAuthenticated
        ));
    }
}
