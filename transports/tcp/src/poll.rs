use alloc::sync::Arc;

use minip2p_platform::EntropySource;
use minip2p_transport::mio::{Registry, Waker, event::Event};
use minip2p_transport::{PollSource, TokenSpace};

use crate::provider::TcpProvider;
use crate::transport::TcpTransport;

/// Forwards to the provider, which owns the sockets.
///
/// A provider that is a [`PollSource`] -- `StdTcpProvider` is -- is what makes
/// [`TcpTransport`] a `BlockingTransport` a std swarm can wait on. The
/// transport's own buffered events need no readiness: its
/// [`next_deadline`](minip2p_transport::Transport::next_deadline) reports them
/// as due now.
impl<P: TcpProvider + PollSource, E: EntropySource> PollSource for TcpTransport<P, E> {
    fn attach(
        &mut self,
        registry: Registry,
        tokens: TokenSpace,
        waker: Arc<Waker>,
    ) -> std::io::Result<()> {
        self.provider_mut().attach(registry, tokens, waker)
    }

    fn dispatch(&mut self, event: &Event) {
        self.provider_mut().dispatch(event);
    }
}
