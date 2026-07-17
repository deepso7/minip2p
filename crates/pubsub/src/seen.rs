//! Recently-seen message ids: TTL-based, capacity-bounded, tick-driven.

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;

/// A message's dedup identity: (`from` bytes, `seqno` bytes).
pub(crate) type MessageId = (Vec<u8>, Vec<u8>);

/// Dedup cache for message ids.
///
/// `order` is append-ordered by expiry because `now_ms` is monotonic, so
/// both GC and capacity eviction pop from the front. The cache is the
/// agent's only timer: [`SeenCache::next_expiry`] feeds `next_timeout`.
#[derive(Debug, Default)]
pub(crate) struct SeenCache {
    ids: BTreeSet<MessageId>,
    order: VecDeque<(u64, MessageId)>,
}

impl SeenCache {
    /// Records `id`; evicts the oldest entries beyond `max_entries`.
    /// Returns `false` when the id was already present.
    pub(crate) fn insert(
        &mut self,
        id: MessageId,
        now_ms: u64,
        ttl_ms: u64,
        max_entries: usize,
    ) -> bool {
        if !self.ids.insert(id.clone()) {
            return false;
        }
        self.order.push_back((now_ms.saturating_add(ttl_ms), id));
        while self.order.len() > max_entries {
            if let Some((_, evicted)) = self.order.pop_front() {
                self.ids.remove(&evicted);
            }
        }
        true
    }

    pub(crate) fn contains(&self, id: &MessageId) -> bool {
        self.ids.contains(id)
    }

    /// Drops entries whose TTL has elapsed.
    pub(crate) fn gc(&mut self, now_ms: u64) {
        while let Some((expires, _)) = self.order.front() {
            if *expires > now_ms {
                break;
            }
            if let Some((_, expired)) = self.order.pop_front() {
                self.ids.remove(&expired);
            }
        }
    }

    /// The earliest expiry, if any entry is live.
    pub(crate) fn next_expiry(&self) -> Option<u64> {
        self.order.front().map(|(expires, _)| *expires)
    }
}
