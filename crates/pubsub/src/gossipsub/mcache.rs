//! Heartbeat-windowed gossipsub message cache.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use crate::message::RawMessage;
use crate::seen::MessageId;

#[derive(Clone, Debug)]
struct CacheEntry {
    message: RawMessage,
    topics: Vec<String>,
    generation: u64,
}

/// Recent validated messages, indexed for IHAVE and IWANT.
#[derive(Debug)]
pub(super) struct MessageCache {
    messages: BTreeMap<MessageId, CacheEntry>,
    history: VecDeque<BTreeMap<MessageId, u64>>,
    insertion_order: VecDeque<(MessageId, u64)>,
    history_len: usize,
    max_messages: usize,
    next_generation: u64,
}

impl MessageCache {
    pub(super) fn new(history_len: usize, max_messages: usize) -> Self {
        let mut history = VecDeque::new();
        history.push_front(BTreeMap::new());
        Self {
            messages: BTreeMap::new(),
            history,
            insertion_order: VecDeque::new(),
            history_len,
            max_messages,
            next_generation: 0,
        }
    }

    pub(super) fn put(&mut self, id: MessageId, message: RawMessage, topics: Vec<String>) {
        if self.messages.contains_key(&id) {
            return;
        }
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.messages.insert(
            id.clone(),
            CacheEntry {
                message,
                topics,
                generation,
            },
        );
        self.history
            .front_mut()
            .expect("message cache always has a current window")
            .insert(id.clone(), generation);
        self.insertion_order.push_back((id, generation));
        while self.messages.len() > self.max_messages {
            if let Some((oldest, generation)) = self.insertion_order.pop_front() {
                self.remove_generation(&oldest, generation);
            }
        }
        self.discard_stale_order_front();
    }

    pub(super) fn get(&self, id: &MessageId) -> Option<&RawMessage> {
        self.messages.get(id).map(|entry| &entry.message)
    }

    pub(super) fn gossip_ids(&self, topic: &str, windows: usize) -> Vec<MessageId> {
        let mut unique = BTreeSet::new();
        for (id, generation) in self.history.iter().take(windows).flatten() {
            if self.messages.get(id).is_some_and(|entry| {
                entry.generation == *generation
                    && entry.topics.iter().any(|candidate| candidate == topic)
            }) {
                unique.insert(id.clone());
            }
        }
        unique.into_iter().collect()
    }

    pub(super) fn shift(&mut self) {
        self.history.push_front(BTreeMap::new());
        while self.history.len() > self.history_len {
            if let Some(expired) = self.history.pop_back() {
                for (id, generation) in expired {
                    if self
                        .messages
                        .get(&id)
                        .is_some_and(|entry| entry.generation == generation)
                    {
                        self.messages.remove(&id);
                    }
                }
            }
        }
        self.discard_stale_order_front();
    }

    fn remove_generation(&mut self, id: &MessageId, generation: u64) {
        if !self
            .messages
            .get(id)
            .is_some_and(|entry| entry.generation == generation)
        {
            return;
        }
        self.messages.remove(id);
        for window in &mut self.history {
            if window.get(id) == Some(&generation) {
                window.remove(id);
                break;
            }
        }
    }

    fn discard_stale_order_front(&mut self) {
        while self
            .insertion_order
            .front()
            .is_some_and(|(id, generation)| {
                !self
                    .messages
                    .get(id)
                    .is_some_and(|entry| entry.generation == *generation)
            })
        {
            self.insertion_order.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(byte: u8) -> RawMessage {
        RawMessage {
            raw: vec![byte],
            ..RawMessage::default()
        }
    }

    #[test]
    fn gossip_and_serving_follow_window_lifetimes() {
        let mut cache = MessageCache::new(5, 8);
        cache.put(vec![1], message(1), vec![String::from("t")]);
        for heartbeat in 0..5 {
            assert_eq!(cache.get(&vec![1]).is_some(), heartbeat < 5);
            assert_eq!(cache.gossip_ids("t", 3).contains(&vec![1]), heartbeat < 3);
            cache.shift();
        }
        assert!(cache.get(&vec![1]).is_none());
    }

    #[test]
    fn capacity_eviction_removes_both_indices() {
        let mut cache = MessageCache::new(5, 2);
        cache.put(vec![1], message(1), vec![String::from("t")]);
        cache.put(vec![2], message(2), vec![String::from("t")]);
        cache.put(vec![3], message(3), vec![String::from("t")]);
        assert!(cache.get(&vec![1]).is_none());
        assert!(!cache.gossip_ids("t", 5).contains(&vec![1]));
        assert!(cache.get(&vec![2]).is_some());
    }

    #[test]
    fn stale_windows_do_not_evict_a_reinserted_id() {
        let mut cache = MessageCache::new(2, 1);
        cache.put(vec![1], message(1), vec![String::from("t")]);
        cache.put(vec![2], message(2), vec![String::from("t")]);
        cache.put(vec![1], message(3), vec![String::from("t")]);

        cache.shift();
        assert_eq!(
            cache.get(&vec![1]).map(|message| message.raw.as_slice()),
            Some(&[3][..])
        );
        cache.shift();
        assert!(cache.get(&vec![1]).is_none());
    }
}
