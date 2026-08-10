use core::time::Duration;

use minip2p_platform::EntropySource;
use minip2p_transport::{BlockingTransport, WaitHandle, WaitOutcome};

use crate::provider::TcpProvider;
use crate::transport::TcpTransport;

/// Blocking readiness waits for providers backed by an operating system.
///
/// Deliberately separate from [`TcpProvider`], for the same reason
/// [`BlockingTransport`] is separate from
/// [`Transport`](minip2p_transport::Transport): blocking a thread needs an OS
/// to block on. An embedded provider drives its stack from an event loop and
/// implements only [`TcpProvider`]; a hosted one adds this so idle drivers
/// sleep on socket readiness instead of spinning.
///
/// Implementing it is what makes [`TcpTransport`] a [`BlockingTransport`].
///
/// # Readiness must survive the wait
///
/// A wait that consumes readiness notifications and discards them would strand
/// the following [`poll`](TcpProvider::poll), which is where sockets are
/// actually serviced. Implementations must retain whatever they learn while
/// waiting.
pub trait BlockingTcpProvider: TcpProvider {
    /// Blocks until a socket may be ready or `timeout` elapses.
    ///
    /// Must not consume input, and must tolerate spurious wakeups: callers
    /// always follow up with [`TcpProvider::poll`].
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome;

    /// Returns a handle that interrupts a wait in progress.
    fn wait_handle(&self) -> WaitHandle;
}

impl<P: BlockingTcpProvider, E: EntropySource> BlockingTransport for TcpTransport<P, E> {
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        if self.has_pending_events() {
            return WaitOutcome::Ready;
        }
        self.provider_mut().wait_for_input(timeout)
    }

    /// Forwards to the provider, which owns the sockets the wait blocks on.
    ///
    /// Inheriting the inert default would hand callers a handle that silently
    /// does nothing while the wait still blocks inside the provider.
    fn wait_handle(&self) -> WaitHandle {
        self.provider().wait_handle()
    }
}
