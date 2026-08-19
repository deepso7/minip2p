use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::RateLimit;

#[derive(Clone, Copy)]
struct Bucket {
    tokens: u32,
    last_refill_ms: u64,
    generation: u64,
}

pub(crate) struct TokenBuckets<K> {
    config: RateLimit,
    buckets: BTreeMap<K, Bucket>,
    due: BTreeMap<u64, Vec<(K, u64)>>,
    next_generation: u64,
}

impl<K: Clone + Ord> TokenBuckets<K> {
    pub(crate) fn new(config: RateLimit) -> Self {
        Self {
            config,
            buckets: BTreeMap::new(),
            due: BTreeMap::new(),
            next_generation: 1,
        }
    }

    pub(crate) fn consume(&mut self, key: K, now_ms: u64) -> bool {
        self.sweep(now_ms);
        let mut bucket = self.buckets.remove(&key).unwrap_or(Bucket {
            tokens: self.config.capacity,
            last_refill_ms: now_ms,
            generation: 0,
        });
        refill(&mut bucket, self.config, now_ms);
        if bucket.tokens == 0 {
            self.schedule(key.clone(), &mut bucket);
            self.buckets.insert(key, bucket);
            return false;
        }
        bucket.tokens -= 1;
        self.schedule(key.clone(), &mut bucket);
        self.buckets.insert(key, bucket);
        true
    }

    pub(crate) fn sweep(&mut self, now_ms: u64) {
        while let Some((&deadline, _)) = self.due.first_key_value() {
            if deadline > now_ms {
                break;
            }
            let entries = self.due.remove(&deadline).unwrap_or_default();
            for (key, generation) in entries {
                let Some(mut bucket) = self.buckets.remove(&key) else {
                    continue;
                };
                if bucket.generation != generation {
                    self.buckets.insert(key, bucket);
                    continue;
                }
                bucket.generation = 0;
                refill(&mut bucket, self.config, now_ms);
                if bucket.tokens < self.config.capacity {
                    self.schedule(key.clone(), &mut bucket);
                    self.buckets.insert(key, bucket);
                }
            }
        }
    }

    pub(crate) fn next_due(&self) -> Option<u64> {
        self.due.first_key_value().map(|(due, _)| *due)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }

    fn schedule(&mut self, key: K, bucket: &mut Bucket) {
        if bucket.generation != 0 {
            return;
        }
        let deadline = bucket
            .last_refill_ms
            .saturating_add(self.config.refill_interval_ms);
        if deadline == u64::MAX {
            return;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        bucket.generation = generation;
        self.due
            .entry(deadline)
            .or_default()
            .push((key, generation));
    }
}

fn refill(bucket: &mut Bucket, config: RateLimit, now_ms: u64) {
    let elapsed = now_ms.saturating_sub(bucket.last_refill_ms);
    let intervals = elapsed / config.refill_interval_ms;
    if intervals == 0 {
        return;
    }
    let added = intervals.min(u32::MAX as u64) as u32;
    bucket.tokens = bucket.tokens.saturating_add(added).min(config.capacity);
    bucket.last_refill_ms = bucket
        .last_refill_ms
        .saturating_add(intervals.saturating_mul(config.refill_interval_ms));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RateLimit;

    #[test]
    fn token_bucket_starts_full_refills_one_per_interval_and_allows_equality() {
        let mut limiter = TokenBuckets::new(RateLimit {
            capacity: 2,
            refill_interval_ms: 10,
        });
        assert!(limiter.consume("peer", 0));
        assert!(limiter.consume("peer", 0));
        assert!(!limiter.consume("peer", 9));
        assert!(limiter.consume("peer", 10));
        assert!(!limiter.consume("peer", 10));
        assert!(limiter.consume("peer", 20));
    }

    #[test]
    fn sweep_processes_every_simultaneously_due_bucket_and_removes_full_entries() {
        let mut limiter = TokenBuckets::new(RateLimit {
            capacity: 1,
            refill_interval_ms: 10,
        });
        for key in 0..1_000 {
            assert!(limiter.consume(key, 5));
        }
        assert_eq!(limiter.len(), 1_000);
        limiter.sweep(15);
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn refill_arithmetic_saturates_at_capacity_and_timeline_end() {
        let mut limiter = TokenBuckets::new(RateLimit {
            capacity: 3,
            refill_interval_ms: 1,
        });

        for _ in 0..3 {
            assert!(limiter.consume(1, u64::MAX - 10));
        }
        assert!(!limiter.consume(1, u64::MAX - 10));

        // Ten elapsed intervals refill only to capacity, even at the end of
        // the monotonic timeline. Further access cannot schedule past MAX.
        assert!(limiter.consume(1, u64::MAX));
        assert!(limiter.consume(1, u64::MAX));
        assert!(limiter.consume(1, u64::MAX));
        assert!(!limiter.consume(1, u64::MAX));
        assert_eq!(limiter.next_due(), None);
    }
}
