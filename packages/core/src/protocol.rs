use alloc::string::String;

use minip2p_identity::PeerId;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Ip4([u8; 4]),
    Ip6([u8; 16]),
    Dns(String),
    Dns4(String),
    Dns6(String),
    Udp(u16),
    QuicV1,
    P2p(PeerId),
}

impl Protocol {
    pub fn is_host(&self) -> bool {
        matches!(
            self,
            Self::Ip4(_) | Self::Ip6(_) | Self::Dns(_) | Self::Dns4(_) | Self::Dns6(_)
        )
    }
}
