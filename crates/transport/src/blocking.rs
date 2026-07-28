use core::time::Duration;

use crate::Transport;

/// Result of [`BlockingTransport::wait_for_input`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Input may be ready; the caller should poll now.
    Ready,
    /// An external handle interrupted the wait.
    ///
    /// Runtime drivers should return control to their caller without treating
    /// this as transport input or a timer expiry.
    Interrupted,
    /// The timeout elapsed without input arriving.
    TimedOut,
    /// The transport cannot wait for readiness; the caller should fall back
    /// to sleeping between polls.
    Unsupported,
}

/// Blocking readiness waits for transports driven by a thread.
///
/// This is deliberately **not** part of the portable [`Transport`] contract.
/// Blocking a thread needs an OS to block on: a `no_std` host drives its
/// transports from an event loop or interrupt handler and idles however its
/// platform allows, using [`Transport::next_deadline`] to decide for how long.
///
/// Adapters that own a socket should implement this with a real readiness wait
/// so idle drivers sleep for the whole timer budget instead of spinning on a
/// fixed cadence. The default implementation reports
/// [`WaitOutcome::Unsupported`], so `impl BlockingTransport for MyTransport {}`
/// is enough to opt a transport into blocking drivers with a sleep fallback.
pub trait BlockingTransport: Transport {
    /// Blocks until new transport input may be available or `timeout` elapses,
    /// whichever comes first.
    ///
    /// Implementations must not consume input and must tolerate spurious
    /// wakeups; callers always follow up with [`Transport::poll`].
    fn wait_for_input(&mut self, timeout: Duration) -> WaitOutcome {
        let _ = timeout;
        WaitOutcome::Unsupported
    }
}
