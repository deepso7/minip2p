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
}

/// Recent validated messages, indexed for IHAVE and IWANT.
#[derive(Debug)]
pub(super) struct MessageCache {
    messages: BTreeMap<MessageId, CacheEntry>,
    history: VecDeque<Vec<MessageId>>,
    insertion_order: VecDeque<MessageId>,
    history_len: usize,
    max_messages: usize,
}

impl MessageCache {
    pub(super) fn new(history_len: usize, max_messages: usize) -> Self {
        let mut history = VecDeque::new();
        history.push_front(Vec::new());
        Self {
            messages: BTreeMap::new(),
            history,
            insertion_order: VecDeque::new(),
            history_len,
            max_messages,
        }
    }

    pub(super) fn put(&mut self, id: MessageId, message: RawMessage, topics: Vec<String>) {
        if self.messages.contains_key(&id) {
            return;
        }
        self.messages
            .insert(id.clone(), CacheEntry { message, topics });
        self.history
            .front_mut()
            .expect("message cache always has a current window")
            .push(id.clone());
        self.insertion_order.push_back(id);
        while self.messages.len() > self.max_messages {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.remove(&oldest);
            }
        }
    }

    pub(super) fn get(&self, id: &MessageId) -> Option<&RawMessage> {
        self.messages.get(id).map(|entry| &entry.message)
    }

    pub(super) fn gossip_ids(&self, topic: &str, windows: usize) -> Vec<MessageId> {
        let mut unique = BTreeSet::new();
        for id in self.history.iter().take(windows).flatten() {
            if self
                .messages
                .get(id)
                .is_some_and(|entry| entry.topics.iter().any(|candidate| candidate == topic))
            {
                unique.insert(id.clone());
            }
        }
        unique.into_iter().collect()
    }

    pub(super) fn shift(&mut self) {
        self.history.push_front(Vec::new());
        while self.history.len() > self.history_len {
            if let Some(expired) = self.history.pop_back() {
                for id in expired {
                    self.remove(&id);
                }
            }
        }
    }

    fn remove(&mut self, id: &MessageId) {
        self.messages.remove(id);
        self.insertion_order.retain(|candidate| candidate != id);
        for window in &mut self.history {
            window.retain(|candidate| candidate != id);
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
}
