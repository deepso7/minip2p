#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub cert_chain_path: Option<String>,
    pub priv_key_path: Option<String>,
    pub verify_peer: bool,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            cert_chain_path: None,
            priv_key_path: None,
            verify_peer: false,
        }
    }
}

impl QuicConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cert_paths(
        mut self,
        cert: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        self.cert_chain_path = Some(cert.into());
        self.priv_key_path = Some(key.into());
        self
    }

    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }
}
