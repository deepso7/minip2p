//! One shared, edge-triggered readiness poll for std hosts (ADR 0013).
//!
//! Blocking a thread needs an OS to block on, so none of this is part of the
//! portable [`Transport`] contract. A std host -- the swarm's `Swarm<T>` --
//! owns one [`SharedPoll`]: one `mio::Poll` and one `mio::Waker`. Every source
//! of input registers with it:
//!
//! - the transport, through [`PollSource::attach`], in its own [`TokenSpace`];
//! - sources the host owns itself (mDNS sockets), through
//!   [`SharedPoll::attach_host_source`], whose readiness only wakes the host;
//! - other threads, through the [`WaitHandle`] (interrupt) and [`WakeHandle`]
//!   (wake only) that share the one `Waker`.
//!
//! A wait therefore blocks once, for everything, on every platform mio
//! supports.

use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::io;
use std::time::Instant;

use mio::event::Event;
use mio::{Events, Poll, Registry, Token, Waker};

use crate::Transport;

/// Bits of a [`TokenSpace`] the [`SharedPoll`] spends on its own prefix.
const HOST_PREFIX_BITS: u32 = 4;
/// The transport's top-level space.
const TRANSPORT_SPACE: usize = 0;
/// The top-level space whose first token is the shared `Waker`'s.
const WAKER_SPACE: usize = (1 << HOST_PREFIX_BITS) - 1;
/// Readiness events collected per harvest. A cap rather than "until empty",
/// so a busy poll cannot hold a drive iteration open: what is left stays
/// queued in the selector for the next harvest.
const EVENTS_PER_HARVEST: usize = 128;

/// Why a [`TokenSpace`] could not be split.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TokenSpaceError {
    /// The prefix would leave no bits for the subspace's own tokens. Nesting
    /// sets of sets is what gets here.
    #[error("a {bits}-bit token space cannot spend {prefix_bits} bits on a prefix")]
    Exhausted {
        /// Bits the space being split has.
        bits: u32,
        /// Bits the prefix asked for.
        prefix_bits: u32,
    },
    /// The index does not fit in the prefix.
    #[error("subspace {index} does not fit in a {prefix_bits}-bit prefix")]
    OutOfRange {
        /// The subspace asked for.
        index: usize,
        /// Bits the prefix has.
        prefix_bits: u32,
    },
}

/// A fixed, aligned range of `mio::Token` values a source allocates from.
///
/// The range is `2^bits` tokens long and starts at a multiple of its length,
/// so the subspace an event belongs to is a matter of its token's high bits:
/// routing needs no table. A source picks tokens with [`token`](Self::token)
/// and maps events back with [`index_of`](Self::index_of). It may reuse a
/// token once it has deregistered the socket that held it; an event for the
/// old socket that arrives afterwards is then a spurious wake on the new one,
/// harmless because sources read until `WouldBlock`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenSpace {
    base: usize,
    bits: u32,
}

impl TokenSpace {
    /// Every token this platform can represent.
    pub const fn full() -> Self {
        Self {
            base: 0,
            bits: usize::BITS,
        }
    }

    /// How many bits of token this space owns: it holds `2^bits` tokens.
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// The `index`-th token of this space, if it has that many.
    pub fn token(&self, index: usize) -> Option<Token> {
        fits(index, self.bits).then_some(Token(self.base | index))
    }

    /// Where `token` sits in this space, if it belongs to it.
    pub fn index_of(&self, token: Token) -> Option<usize> {
        let mask = mask(self.bits);
        (token.0 & !mask == self.base).then_some(token.0 & mask)
    }

    /// The `index`-th of the `2^prefix_bits` equal subspaces of this one.
    ///
    /// Checked: a split that would leave the subspace no tokens, or an index
    /// the prefix cannot hold, is a [`TokenSpaceError`] rather than an
    /// overflow into a sibling's range.
    pub fn subspace(&self, prefix_bits: u32, index: usize) -> Result<Self, TokenSpaceError> {
        if prefix_bits == 0 || prefix_bits >= self.bits {
            return Err(TokenSpaceError::Exhausted {
                bits: self.bits,
                prefix_bits,
            });
        }
        if !fits(index, prefix_bits) {
            return Err(TokenSpaceError::OutOfRange { index, prefix_bits });
        }
        let bits = self.bits - prefix_bits;
        Ok(Self {
            base: self.base | (index << bits),
            bits,
        })
    }

    /// Which of the `2^prefix_bits` subspaces `token` falls in, if it belongs
    /// to this space at all. The inverse of [`subspace`](Self::subspace).
    pub fn subspace_of(&self, prefix_bits: u32, token: Token) -> Option<usize> {
        let index = self.index_of(token)?;
        let bits = self.bits.checked_sub(prefix_bits)?;
        Some(index.checked_shr(bits).unwrap_or(0))
    }
}

/// Whether `index` fits in `bits` bits.
fn fits(index: usize, bits: u32) -> bool {
    index.checked_shr(bits).unwrap_or(0) == 0
}

/// The low `bits` bits set.
fn mask(bits: u32) -> usize {
    1usize.checked_shl(bits).map_or(usize::MAX, |bit| bit - 1)
}

/// Something with sockets that registers them with a host's shared poll.
///
/// # Lifecycle
///
/// [`attach`](Self::attach) is called once, with a registry clone, a
/// [`TokenSpace`] to allocate from, and the host's one `Waker`. The source
/// keeps the registry to register sockets it creates later, uses only tokens
/// from its space, and may keep the `Waker`: mio allows one per poll, so a
/// source must never create its own. A source with no socket at all (an
/// in-memory transport) keeps a pending-input flag of its own and calls that
/// `Waker` when input arrives.
///
/// [`dispatch`](Self::dispatch) hands over readiness for a token this source
/// registered. The source records it; the next [`Transport::poll`] consumes
/// it.
///
/// **Before attach** (a `SwarmCore` host driving a std transport directly),
/// a source treats every socket as possibly ready on each poll and reads until
/// `WouldBlock`, so it still makes progress without dispatched readiness.
///
/// # Edge-triggered rule
///
/// mio reports readiness edges, not levels, on every platform. After
/// `dispatch`, a source reads each ready socket until `WouldBlock`, or
/// remembers what it has not read yet (a receive budget ran out, work was
/// deferred) and reports [`Transport::next_deadline`] as due now until a poll
/// has consumed it. Readiness must never be lost when a source is dispatched
/// to but not polled before the host's next wait: the edge will not come
/// again.
pub trait PollSource {
    /// Registers this source's sockets with the host's shared poll.
    fn attach(&mut self, registry: Registry, tokens: TokenSpace, waker: Arc<Waker>)
    -> io::Result<()>;

    /// Records readiness for one of this source's tokens.
    fn dispatch(&mut self, event: &Event);
}

impl<S: PollSource + ?Sized> PollSource for alloc::boxed::Box<S> {
    fn attach(
        &mut self,
        registry: Registry,
        tokens: TokenSpace,
        waker: Arc<Waker>,
    ) -> io::Result<()> {
        (**self).attach(registry, tokens, waker)
    }

    fn dispatch(&mut self, event: &Event) {
        (**self).dispatch(event);
    }
}

/// A [`Transport`] a thread can block on: one that is also a [`PollSource`].
///
/// Implemented automatically for every such type; the std `Swarm<T>` requires
/// it.
pub trait BlockingTransport: Transport + PollSource {}

impl<T: Transport + PollSource + ?Sized> BlockingTransport for T {}

/// Cloneable handle that interrupts a [`SharedPoll`] wait from another thread.
///
/// Sets a flag, then wakes the poll, so the wait reports an interrupt rather
/// than a plain wakeup. Interrupts that arrive before one is consumed coalesce
/// into one; an interrupt with no wait in progress is kept for the next one.
#[derive(Clone)]
pub struct WaitHandle {
    flag: Arc<AtomicBool>,
    waker: Arc<Waker>,
}

impl WaitHandle {
    /// Interrupts the current wait, or the next one if none is active.
    pub fn interrupt(&self) {
        self.flag.store(true, Ordering::SeqCst);
        // A poll that is gone has no wait left to interrupt.
        drop(self.waker.wake());
    }
}

impl fmt::Debug for WaitHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WaitHandle").finish_non_exhaustive()
    }
}

/// Cloneable handle that wakes a [`SharedPoll`] wait without interrupting it.
///
/// For host work finished on another thread, such as a name lookup: the wait
/// ends with a host wakeup, never with an interrupt.
#[derive(Clone)]
pub struct WakeHandle {
    waker: Arc<Waker>,
}

impl WakeHandle {
    /// Wakes the current wait, or the next one if none is active.
    pub fn wake(&self) {
        // A poll that is gone has nothing left to wake.
        drop(self.waker.wake());
    }
}

impl fmt::Debug for WakeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WakeHandle").finish_non_exhaustive()
    }
}

/// One `mio::Poll` and its one `Waker`, shared by a transport, host-owned
/// sources and other threads.
///
/// The token range is split by a 4-bit prefix: space 0 is the transport's,
/// spaces 1 to 14 go to host sources, and the first token of space 15 is the
/// `Waker`'s. That leaves 2^28 tokens per space on a 32-bit target.
///
/// A host drives it with [`harvest`](Self::harvest), which dispatches the
/// transport's readiness and records everything else: a pending host wake
/// (a `Waker` event, or readiness in a host source's space), read with
/// [`take_wake`](Self::take_wake), and a pending interrupt, read with
/// [`take_interrupt`](Self::take_interrupt). Neither is cleared by a
/// harvest, so nothing pending is lost to one that ended early.
pub struct SharedPoll {
    poll: Poll,
    events: Events,
    waker: Arc<Waker>,
    interrupt: Arc<AtomicBool>,
    /// A host wake harvested and not yet taken.
    woken: bool,
    /// The next top-level space to hand a host source.
    next_host_space: usize,
}

impl fmt::Debug for SharedPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPoll")
            .field("woken", &self.woken)
            .finish_non_exhaustive()
    }
}

impl SharedPoll {
    /// Opens the poll and its `Waker`.
    pub fn new() -> io::Result<Self> {
        let poll = Poll::new()?;
        let waker_token = top_level(WAKER_SPACE)
            .token(0)
            .ok_or_else(|| io::Error::other("the waker token does not fit"))?;
        let waker = Arc::new(Waker::new(poll.registry(), waker_token)?);
        Ok(Self {
            poll,
            events: Events::with_capacity(EVENTS_PER_HARVEST),
            waker,
            interrupt: Arc::default(),
            woken: false,
            next_host_space: TRANSPORT_SPACE + 1,
        })
    }

    /// Attaches the transport this poll dispatches to, in space 0.
    pub fn attach<S: PollSource + ?Sized>(&mut self, transport: &mut S) -> io::Result<()> {
        transport.attach(
            self.poll.registry().try_clone()?,
            top_level(TRANSPORT_SPACE),
            Arc::clone(&self.waker),
        )
    }

    /// Attaches a source the host services itself, in the next spare space.
    ///
    /// The source is never dispatched to: readiness in its space only
    /// records a host wake, after which the host services it (mDNS reads
    /// every socket on its tick). Fails once the 14 spare spaces are spent.
    pub fn attach_host_source<S: PollSource + ?Sized>(&mut self, source: &mut S) -> io::Result<()> {
        if self.next_host_space >= WAKER_SPACE {
            return Err(io::Error::other(TokenSpaceError::OutOfRange {
                index: self.next_host_space,
                prefix_bits: HOST_PREFIX_BITS,
            }));
        }
        let space = top_level(self.next_host_space);
        source.attach(
            self.poll.registry().try_clone()?,
            space,
            Arc::clone(&self.waker),
        )?;
        self.next_host_space += 1;
        Ok(())
    }

    /// A handle that interrupts this poll's waits.
    pub fn wait_handle(&self) -> WaitHandle {
        WaitHandle {
            flag: Arc::clone(&self.interrupt),
            waker: Arc::clone(&self.waker),
        }
    }

    /// A handle that wakes this poll's waits without interrupting them.
    pub fn wake_handle(&self) -> WakeHandle {
        WakeHandle {
            waker: Arc::clone(&self.waker),
        }
    }

    /// Whether an interrupt is pending, clearing it.
    ///
    /// The flag is only ever cleared here, so a host calls this exactly when
    /// it is about to report the interrupt. One that arrives after the swap
    /// stays pending for the next call.
    pub fn take_interrupt(&self) -> bool {
        self.interrupt.swap(false, Ordering::SeqCst)
    }

    /// Whether a host wake is pending, clearing it.
    ///
    /// A `Waker` event may be an interrupt's as well as a wake's: it is
    /// counted as a host wake either way, an occasional extra host step being
    /// cheaper than tracking where each wake came from.
    pub fn take_wake(&mut self) -> bool {
        core::mem::take(&mut self.woken)
    }

    /// Collects one bounded batch of readiness, blocking up to `timeout`, and
    /// dispatches the transport's share of it to `transport`.
    ///
    /// Returns how many events arrived. `EINTR` is retried against the
    /// original deadline; any other poll error is returned.
    pub fn harvest<S: PollSource + ?Sized>(
        &mut self,
        transport: &mut S,
        timeout: Duration,
    ) -> io::Result<usize> {
        let Self { poll, events, .. } = self;
        poll_retrying(timeout, |timeout| poll.poll(events, Some(timeout)))?;
        let transport_space = top_level(TRANSPORT_SPACE);
        let mut count = 0;
        for event in self.events.iter() {
            count += 1;
            if transport_space.index_of(event.token()).is_some() {
                transport.dispatch(event);
            } else {
                // The `Waker` (host work, socket-less input, or an
                // interrupt), or a host source's socket.
                self.woken = true;
            }
        }
        #[cfg(feature = "bench")]
        crate::bench::record_wait(timeout, count);
        Ok(count)
    }
}

/// The `index`-th top-level space of the shared poll.
fn top_level(index: usize) -> TokenSpace {
    TokenSpace::full()
        .subspace(HOST_PREFIX_BITS, index)
        .expect("every top-level space fits a 4-bit prefix")
}

/// Runs `poll` until it returns something other than `EINTR`, shrinking each
/// retry's timeout so the whole call still ends at the original deadline.
fn poll_retrying(
    timeout: Duration,
    mut poll: impl FnMut(Duration) -> io::Result<()>,
) -> io::Result<()> {
    let deadline = Instant::now().checked_add(timeout);
    let mut remaining = timeout;
    loop {
        match poll(remaining) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                remaining = match deadline {
                    Some(deadline) => deadline.saturating_duration_since(Instant::now()),
                    None => remaining,
                };
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn subspaces_tile_their_parent_without_overlap() {
        let parent = TokenSpace::full().subspace(4, 3).expect("top level");
        let first = parent.subspace(8, 0).expect("first");
        let second = parent.subspace(8, 1).expect("second");
        let last_token = first.token((1 << first.bits()) - 1).expect("last of first");
        assert_eq!(first.index_of(last_token), Some((1 << first.bits()) - 1));
        assert_eq!(second.index_of(last_token), None, "no overlap");
        assert_eq!(parent.subspace_of(8, last_token), Some(0));
        let in_second = second.token(5).expect("token");
        assert_eq!(parent.subspace_of(8, in_second), Some(1));
        assert_eq!(second.index_of(in_second), Some(5));
        assert_eq!(first.token(1 << first.bits()), None, "past the end");
    }

    #[test]
    fn splitting_a_space_too_far_is_a_typed_error() {
        let mut space = TokenSpace::full();
        let mut error = None;
        for _ in 0..usize::BITS {
            match space.subspace(8, 255) {
                Ok(next) => space = next,
                Err(failed) => {
                    error = Some(failed);
                    break;
                }
            }
        }
        assert!(
            matches!(error, Some(TokenSpaceError::Exhausted { prefix_bits: 8, .. })),
            "{error:?}"
        );
        assert_eq!(
            TokenSpace::full().subspace(8, 256),
            Err(TokenSpaceError::OutOfRange {
                index: 256,
                prefix_bits: 8
            })
        );
    }

    #[test]
    fn eintr_is_retried_against_the_original_deadline() {
        let mut timeouts = Vec::new();
        let result = poll_retrying(Duration::from_millis(50), |timeout| {
            timeouts.push(timeout);
            if timeouts.len() < 3 {
                std::thread::sleep(Duration::from_millis(10));
                Err(io::ErrorKind::Interrupted.into())
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
        assert_eq!(timeouts.len(), 3);
        assert!(
            timeouts[2] <= Duration::from_millis(31),
            "the retry spent the time already waited: {timeouts:?}"
        );
    }

    #[test]
    fn other_poll_errors_reach_the_caller() {
        let mut calls = 0;
        let result = poll_retrying(Duration::from_millis(5), |_| {
            calls += 1;
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(
            result.map_err(|error| error.kind()),
            Err(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(calls, 1, "no retry, no sleep fallback");
    }

    /// A socket-less source: input arrives on another thread, which wakes
    /// the poll with the shared `Waker`.
    #[derive(Default)]
    struct Socketless {
        waker: Option<Arc<Waker>>,
        dispatched: usize,
    }

    impl PollSource for Socketless {
        fn attach(&mut self, _: Registry, _: TokenSpace, waker: Arc<Waker>) -> io::Result<()> {
            self.waker = Some(waker);
            Ok(())
        }

        fn dispatch(&mut self, _: &Event) {
            self.dispatched += 1;
        }
    }

    #[test]
    fn wakes_and_interrupts_share_one_waker_without_mixing_up() {
        let mut poll = SharedPoll::new().expect("poll");
        let mut first = Socketless::default();
        let mut second = Socketless::default();
        poll.attach(&mut first).expect("attach");
        poll.attach_host_source(&mut second).expect("host source");

        // Input and a host wake alone never read as an interrupt.
        first.waker.as_ref().expect("waker").wake().expect("wake");
        poll.wake_handle().wake();
        poll.harvest(&mut first, Duration::from_secs(5)).expect("harvest");
        assert!(!poll.take_interrupt());
        assert!(poll.take_wake());

        // Coinciding with an interrupt, both survive.
        second.waker.as_ref().expect("waker").wake().expect("wake");
        poll.wait_handle().interrupt();
        poll.wait_handle().interrupt();
        poll.harvest(&mut first, Duration::from_secs(5)).expect("harvest");
        assert!(poll.take_interrupt(), "pending interrupts coalesce into one");
        assert!(!poll.take_interrupt());
        assert!(poll.take_wake());
        assert_eq!(first.dispatched, 0, "the waker is nobody's socket");
    }

    #[test]
    fn host_spaces_run_out_with_an_error() {
        let mut poll = SharedPoll::new().expect("poll");
        let mut sources: Vec<Socketless> = vec![];
        for _ in 1..WAKER_SPACE {
            let mut source = Socketless::default();
            poll.attach_host_source(&mut source).expect("spare space");
            sources.push(source);
        }
        assert!(
            poll.attach_host_source(&mut Socketless::default())
                .is_err()
        );
    }
}
