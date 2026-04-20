#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PeerSendPolicy {
    #[default]
    Primary,
    OldestConnected,
    NewestConnected,
}
