pub mod peer;
pub mod tls;

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// Blocks until `socket` becomes readable or `deadline` passes. mio is
/// edge-triggered, so a peer that hit its receive cap must not wait (see
/// `Peer::next_timeout`).
pub struct Waiter {
    poll: mio::Poll,
    events: mio::Events,
}

impl Waiter {
    pub fn new(socket: &impl AsRawFd) -> Self {
        let poll = mio::Poll::new().unwrap();
        poll.registry()
            .register(&mut mio::unix::SourceFd(&socket.as_raw_fd()), mio::Token(0), mio::Interest::READABLE)
            .unwrap();
        Self { poll, events: mio::Events::with_capacity(4) }
    }
    pub fn wait(&mut self, deadline: Option<Instant>) {
        let timeout = deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::from_millis(50))
            .min(Duration::from_millis(50));
        if timeout.is_zero() { return; }
        let _ = self.poll.poll(&mut self.events, Some(timeout));
    }
}

/// Time handed to quinn: real `Instant::now()`, or with `QCLOCK=ms` the
/// host-style millisecond sample (`base + whole ms elapsed`).
pub fn clock(base: Instant) -> Instant {
    static MS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *MS.get_or_init(|| std::env::var("QCLOCK").as_deref() == Ok("ms")) {
        base + Duration::from_millis(base.elapsed().as_millis() as u64)
    } else {
        Instant::now()
    }
}

/// Counts allocations process-wide (all threads).
pub struct Counting;
pub static ALLOCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: std::alloc::Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        unsafe { std::alloc::System.realloc(p, l, n) }
    }
}
