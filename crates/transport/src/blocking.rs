use alloc::sync::Arc;
use core::fmt;
use core::time::Duration;

use crate::Transport;

/// Cloneable handle that interrupts a transport's current readiness wait.
///
/// Transport-neutral: each adapter supplies its own interrupt action, so a
/// host holding one of these does not need to know which transport it is
/// driving. Interrupting when no wait is active makes the *next* wait return
/// immediately, so a handle cannot lose a wakeup to a race with the waiter.
///
/// Typical use is a background thread nudging a blocked drive loop after
/// queueing outbound work.
#[derive(Clone)]
pub struct WaitHandle(Option<Arc<dyn Fn() + Send + Sync>>);

impl WaitHandle {
    /// Creates a handle that runs `interrupt` to wake a blocked wait.
    pub fn new(interrupt: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(interrupt)))
    }

    /// Creates a handle for a transport that cannot be interrupted.
    ///
    /// [`interrupt`](Self::interrupt) does nothing. A driver waiting on such a
    /// transport still wakes on its own timer budget, so this degrades
    /// latency, never correctness.
    pub fn noop() -> Self {
        Self(None)
    }

    /// Returns whether this handle can actually interrupt a wait.
    pub fn is_noop(&self) -> bool {
        self.0.is_none()
    }

    /// Interrupts any current wait, or the next one if none is active.
    pub fn interrupt(&self) {
        if let Some(interrupt) = &self.0 {
            interrupt();
        }
    }

    /// Combines several handles into one that interrupts all of them.
    ///
    /// A host driving more than one transport -- QUIC and TCP side by side --
    /// wakes every waiter with a single call. Handles that cannot interrupt
    /// are skipped; if none can, the result is a no-op handle.
    pub fn combined(handles: impl IntoIterator<Item = Self>) -> Self {
        let interrupts: alloc::vec::Vec<_> =
            handles.into_iter().filter_map(|handle| handle.0).collect();
        if interrupts.is_empty() {
            return Self::noop();
        }
        Self::new(move || {
            for interrupt in &interrupts {
                interrupt();
            }
        })
    }
}

impl fmt::Debug for WaitHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WaitHandle")
            .field(&if self.is_noop() { "noop" } else { "active" })
            .finish()
    }
}

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
///
/// # Decorators must forward every method
///
/// The defaults are only correct together, for a leaf transport with nothing
/// to wake. A transport that wraps another and forwards
/// [`wait_for_input`](Self::wait_for_input) must also forward
/// [`wait_handle`](Self::wait_handle): otherwise callers get an inert handle
/// while the wait still blocks inside the inner transport, and interrupting
/// silently does nothing. On unix it forwards
/// `readiness_fd` too, or a
/// [`TransportSet`](crate::TransportSet) holding it falls back to taking turns.
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

    /// Returns a handle that interrupts this transport's waits.
    ///
    /// The default cannot interrupt anything; adapters that own a wakeable
    /// primitive should override it so hosts can nudge a blocked drive loop.
    /// A transport wrapping another must forward this whenever it forwards
    /// [`wait_for_input`](Self::wait_for_input) -- the handle has to reach
    /// whichever transport actually blocks.
    fn wait_handle(&self) -> WaitHandle {
        WaitHandle::noop()
    }

    /// The file descriptor this transport's waits block on, so a host
    /// waiting on several transports can block on all of them at once.
    ///
    /// [`TransportSet`](crate::TransportSet) uses it to wait on every member
    /// in one level-triggered `poll(2)` rather than in turns. The fd only has
    /// to signal *maybe*: when it reads as ready, the set asks every member
    /// again with a zero-timeout [`wait_for_input`](Self::wait_for_input).
    /// For a mio-backed adapter it is the selector's own fd, from
    /// `Registry::as_fd()`.
    ///
    /// # Contract
    ///
    /// - **Stable:** the same fd for the transport's whole lifetime.
    /// - **Drain before block:** a zero-timeout `wait_for_input` that answers
    ///   [`WaitOutcome::TimedOut`] must first have harvested everything
    ///   pending on the fd, so it is not left readable by stale readiness.
    ///   Harvesting must not lose state: readiness folded into socket flags,
    ///   deferred work and pending interrupts must still be seen by the next
    ///   [`Transport::poll`] or wait. Break this and a set's wait spins on a
    ///   readable fd rather than blocking -- wasteful, but visible, and never a
    ///   lost wakeup.
    /// - **Interrupts:** [`wait_handle`](Self::wait_handle) must make the fd
    ///   readable, so the set's one handle reaches a set blocked in `poll(2)`.
    ///
    /// The default is `None`, and a set with any parking member that has no
    /// fd falls back to taking short turns between members, as it does on
    /// non-unix targets and if `poll(2)` fails. A wrapper that forwards
    /// [`wait_for_input`](Self::wait_for_input) must forward this too.
    #[cfg(unix)]
    fn readiness_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;
    use core::sync::atomic::{AtomicUsize, Ordering};

    fn counter() -> (WaitHandle, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&count);
        (
            WaitHandle::new(move || {
                observed.fetch_add(1, Ordering::SeqCst);
            }),
            count,
        )
    }

    #[test]
    fn interrupt_runs_the_adapter_action() {
        let (handle, count) = counter();
        assert!(!handle.is_noop());

        handle.interrupt();
        handle.interrupt();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn clones_share_one_action() {
        let (handle, count) = counter();
        let clone = handle.clone();

        clone.interrupt();
        handle.interrupt();
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "a cloned handle must drive the same waiter"
        );
    }

    #[test]
    fn noop_handles_are_inert() {
        let handle = WaitHandle::noop();
        assert!(handle.is_noop());
        // Must not panic: a transport with nothing to wake is legal.
        handle.interrupt();
    }

    #[test]
    fn combined_wakes_every_transport() {
        // The multi-transport case: one call must reach QUIC and TCP alike.
        let (first, first_count) = counter();
        let (second, second_count) = counter();
        let combined = WaitHandle::combined(vec![first, second, WaitHandle::noop()]);

        assert!(!combined.is_noop());
        combined.interrupt();
        assert_eq!(first_count.load(Ordering::SeqCst), 1);
        assert_eq!(second_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn combining_only_inert_handles_stays_inert() {
        assert!(WaitHandle::combined(vec![WaitHandle::noop(), WaitHandle::noop()]).is_noop());
        assert!(WaitHandle::combined(vec![]).is_noop());
    }

    #[test]
    fn debug_distinguishes_inert_handles() {
        let (handle, _count) = counter();
        assert_eq!(format!("{handle:?}"), "WaitHandle(\"active\")");
        assert_eq!(format!("{:?}", WaitHandle::noop()), "WaitHandle(\"noop\")");
    }
}
