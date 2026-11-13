//! Receiver-side directory: which peers hold reservations on which member.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use minip2p_core::{FrameExchange, PeerId};

use super::codec::{DirectoryMessage, MAX_MESH_MESSAGE_SIZE, MeshMessageError};

/// Default for [`Directory::new`]'s per-member entry cap.
pub const DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER: usize = 4096;

/// One member's claim that it holds a reservation for a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Claim<'a> {
    /// The holding member's backbone peer id.
    pub member: &'a PeerId,
    /// The reservation's expiry, UTC UNIX seconds, as the member announced it.
    pub expires_unix: u64,
}

/// What the directory did with bytes from a directory stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryInput {
    /// The stream is not the member's current directory stream (superseded,
    /// already ended, or never opened); the bytes changed nothing.
    Ignored,
    /// Complete frames, if any, were applied.
    Applied,
    /// Frames were applied and this input carried the `Synced` that made the
    /// member synced. Pending CONNECTs waiting on this member can look again.
    Synced,
    /// The member broke the protocol. Its entries were dropped and the stream
    /// is no longer current; the caller must reset the stream.
    Reset(DirectoryResetReason),
}

/// Why a directory stream must be reset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectoryResetReason {
    /// A frame could not be decoded.
    Malformed(MeshMessageError),
    /// A `Present` for a new peer would exceed the per-member entry cap.
    TooManyEntries,
}

/// Directory state for one connected member.
#[derive(Clone, Debug)]
struct Member<S> {
    /// The current inbound directory stream and its frame buffer.
    stream: Option<(S, FrameExchange)>,
    /// Whether the current stream has delivered `Synced`.
    synced: bool,
    /// Reserved peer to its expiry, UTC UNIX seconds.
    entries: BTreeMap<PeerId, u64>,
}

impl<S> Member<S> {
    fn new() -> Self {
        Self {
            stream: None,
            synced: false,
            entries: BTreeMap::new(),
        }
    }

    /// Forgets the current stream and everything it said.
    fn clear(&mut self) {
        self.stream = None;
        self.synced = false;
        self.entries.clear();
    }
}

/// A mesh node's view of which peers hold reservations on which other member,
/// built from the members' directory streams.
///
/// Members are keyed by backbone peer id. `S` identifies a stream (the agent
/// uses its `StreamKey`); the directory only compares it for equality. Each
/// member has at most one current inbound directory stream: a newer one
/// supersedes it, and input on a superseded stream is ignored, so it cannot
/// erase the newer stream's snapshot. Time is caller-supplied UNIX seconds,
/// used only to skip expired entries when reading claims.
#[derive(Clone, Debug)]
pub struct Directory<S> {
    members: BTreeMap<PeerId, Member<S>>,
    max_entries_per_member: usize,
}

impl<S: Eq> Default for Directory<S> {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DIRECTORY_ENTRIES_PER_MEMBER)
    }
}

impl<S: Eq> Directory<S> {
    /// An empty directory holding at most `max_entries_per_member` peers per
    /// member.
    pub fn new(max_entries_per_member: usize) -> Self {
        Self {
            members: BTreeMap::new(),
            max_entries_per_member,
        }
    }

    /// Records a backbone connection to `member`. Until its directory stream
    /// delivers `Synced`, the member counts as unsynced. A no-op for a member
    /// already connected.
    pub fn member_connected(&mut self, member: PeerId) {
        self.members.entry(member).or_insert_with(Member::new);
    }

    /// Records that `member`'s backbone connection closed, dropping all its
    /// entries. Returns whether the member was connected.
    pub fn member_disconnected(&mut self, member: &PeerId) -> bool {
        self.members.remove(member).is_some()
    }

    /// Makes `stream` `member`'s current inbound directory stream, connecting
    /// the member if needed. Any previous stream is superseded: the member's
    /// entries are cleared and it is unsynced until `stream` delivers `Synced`.
    pub fn stream_opened(&mut self, member: PeerId, stream: S) {
        let state = self.members.entry(member).or_insert_with(Member::new);
        state.clear();
        state.stream = Some((
            stream,
            FrameExchange::with_trailing(MAX_MESH_MESSAGE_SIZE, usize::MAX),
        ));
    }

    /// Applies bytes read from `member`'s directory stream `stream`.
    ///
    /// Frames may arrive split or coalesced across calls. Every complete frame
    /// is applied before this returns; see [`DirectoryInput`] for the outcome.
    pub fn stream_data(&mut self, member: &PeerId, stream: &S, data: &[u8]) -> DirectoryInput {
        let max_entries = self.max_entries_per_member;
        let Some(state) = self.members.get_mut(member) else {
            return DirectoryInput::Ignored;
        };
        let Some((_, frames)) = state
            .stream
            .as_mut()
            .filter(|(current, _)| current == stream)
        else {
            return DirectoryInput::Ignored;
        };

        let mut became_synced = false;
        let result = frames
            .push(data)
            .map_err(MeshMessageError::from)
            .and_then(|()| {
                while let Some(message) = frames.next_frame(DirectoryMessage::decode)? {
                    match message {
                        DirectoryMessage::Present { peer, expires_unix } => {
                            if !state.entries.contains_key(&peer)
                                && state.entries.len() >= max_entries
                            {
                                return Ok(Some(DirectoryResetReason::TooManyEntries));
                            }
                            state.entries.insert(peer, expires_unix);
                        }
                        DirectoryMessage::Gone { peer } => {
                            state.entries.remove(&peer);
                        }
                        DirectoryMessage::Synced => {
                            became_synced |= !state.synced;
                            state.synced = true;
                        }
                    }
                }
                Ok(None)
            });

        let reset = match result {
            Ok(None) if became_synced => return DirectoryInput::Synced,
            Ok(None) => return DirectoryInput::Applied,
            Ok(Some(reason)) => reason,
            Err(error) => DirectoryResetReason::Malformed(error),
        };
        state.clear();
        DirectoryInput::Reset(reset)
    }

    /// Records that `member`'s directory stream `stream` ended (closed or
    /// reset). If it is the current stream, the member's entries are dropped
    /// and it is unsynced until a new stream syncs. Returns whether the
    /// stream was current; a superseded stream's end changes nothing.
    pub fn stream_ended(&mut self, member: &PeerId, stream: &S) -> bool {
        let Some(state) = self.members.get_mut(member) else {
            return false;
        };
        if state
            .stream
            .as_ref()
            .is_none_or(|(current, _)| current != stream)
        {
            return false;
        }
        state.clear();
        true
    }

    /// Every unexpired remote claim on `destination`, in the order an entry
    /// node should try them: latest `expires_unix` first, ties broken by the
    /// lower member peer id. An entry expiring at or before `now_unix` is not
    /// a claim.
    pub fn claims(&self, destination: &PeerId, now_unix: u64) -> Vec<Claim<'_>> {
        let mut claims: Vec<Claim<'_>> = self
            .members
            .iter()
            .filter_map(|(member, state)| {
                let expires_unix = *state.entries.get(destination)?;
                (expires_unix > now_unix).then_some(Claim {
                    member,
                    expires_unix,
                })
            })
            .collect();
        // Members iterate in peer id order and the sort is stable, so equal
        // expiries keep the lower peer id first.
        claims.sort_by_key(|claim| core::cmp::Reverse(claim.expires_unix));
        claims
    }

    /// Whether any connected member has not yet delivered `Synced` on its
    /// current directory stream. A CONNECT with no claim waits while this
    /// holds.
    pub fn has_unsynced_member(&self) -> bool {
        self.members.values().any(|state| !state.synced)
    }

    /// Whether `member` is connected and its current stream has delivered
    /// `Synced`.
    pub fn is_synced(&self, member: &PeerId) -> bool {
        self.members.get(member).is_some_and(|state| state.synced)
    }

    /// How many peers `member` currently claims, expired entries included.
    pub fn entry_count(&self, member: &PeerId) -> usize {
        self.members
            .get(member)
            .map_or(0, |state| state.entries.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::from_public_key_protobuf(&[seed])
    }

    fn present(seed: u8, expires_unix: u64) -> Vec<u8> {
        DirectoryMessage::Present {
            peer: peer(seed),
            expires_unix,
        }
        .encode_frame()
    }

    fn gone(seed: u8) -> Vec<u8> {
        DirectoryMessage::Gone { peer: peer(seed) }.encode_frame()
    }

    fn synced() -> Vec<u8> {
        DirectoryMessage::Synced.encode_frame()
    }

    fn members(directory: &Directory<u32>, destination: u8) -> Vec<PeerId> {
        directory
            .claims(&peer(destination), 0)
            .into_iter()
            .map(|claim| claim.member.clone())
            .collect()
    }

    const A: u8 = 100;
    const B: u8 = 101;

    #[test]
    fn snapshot_replaces_entries_and_ends_synced() {
        let mut directory = Directory::default();
        directory.member_connected(peer(A));
        assert!(directory.has_unsynced_member());

        directory.stream_opened(peer(A), 1);
        let snapshot = [present(1, 10), present(2, 10), synced()].concat();
        // Split mid-frame to show frames are buffered across reads.
        let (head, tail) = snapshot.split_at(5);
        assert_eq!(
            directory.stream_data(&peer(A), &1, head),
            DirectoryInput::Applied
        );
        assert_eq!(
            directory.stream_data(&peer(A), &1, tail),
            DirectoryInput::Synced
        );
        assert!(directory.is_synced(&peer(A)));
        assert!(!directory.has_unsynced_member());
        assert_eq!(directory.entry_count(&peer(A)), 2);

        // A fresh stream's snapshot replaces the old entries.
        directory.stream_opened(peer(A), 2);
        assert!(!directory.is_synced(&peer(A)));
        let resnapshot = [present(3, 10), synced()].concat();
        assert_eq!(
            directory.stream_data(&peer(A), &2, &resnapshot),
            DirectoryInput::Synced
        );
        assert_eq!(members(&directory, 1), []);
        assert_eq!(members(&directory, 3), [peer(A)]);
    }

    #[test]
    fn gone_stream_end_and_disconnect_remove_entries() {
        let mut directory = Directory::default();
        directory.stream_opened(peer(A), 1);
        let input = [present(1, 10), present(2, 10), synced(), gone(1)].concat();
        directory.stream_data(&peer(A), &1, &input);
        assert_eq!(members(&directory, 1), []);
        assert_eq!(members(&directory, 2), [peer(A)]);

        assert!(directory.stream_ended(&peer(A), &1));
        assert_eq!(members(&directory, 2), []);
        // Still connected, so unsynced until a new stream syncs.
        assert!(directory.has_unsynced_member());

        directory.stream_opened(peer(A), 2);
        directory.stream_data(&peer(A), &2, &[present(2, 10), synced()].concat());
        assert!(directory.member_disconnected(&peer(A)));
        assert_eq!(members(&directory, 2), []);
        assert!(!directory.has_unsynced_member());
    }

    #[test]
    fn superseded_stream_input_changes_nothing() {
        let mut directory = Directory::default();
        directory.stream_opened(peer(A), 1);
        directory.stream_data(&peer(A), &1, &present(1, 10));
        directory.stream_opened(peer(A), 2);
        directory.stream_data(&peer(A), &2, &[present(2, 10), synced()].concat());

        assert_eq!(
            directory.stream_data(&peer(A), &1, &[gone(2), present(1, 10), synced()].concat()),
            DirectoryInput::Ignored
        );
        assert!(!directory.stream_ended(&peer(A), &1));
        assert_eq!(members(&directory, 1), []);
        assert_eq!(members(&directory, 2), [peer(A)]);
        assert!(directory.is_synced(&peer(A)));
    }

    #[test]
    fn cap_and_malformed_frames_reset_and_drop_entries() {
        let mut directory = Directory::new(2);
        directory.stream_opened(peer(A), 1);
        let input = [present(1, 10), present(2, 10), synced(), present(2, 20)].concat();
        assert_eq!(
            directory.stream_data(&peer(A), &1, &input),
            DirectoryInput::Synced,
            "renewing a held peer does not count against the cap"
        );
        assert_eq!(
            directory.stream_data(&peer(A), &1, &present(3, 10)),
            DirectoryInput::Reset(DirectoryResetReason::TooManyEntries)
        );
        assert_eq!(directory.entry_count(&peer(A)), 0);
        assert!(!directory.is_synced(&peer(A)));
        // The reset stream is no longer current.
        assert_eq!(
            directory.stream_data(&peer(A), &1, &present(1, 10)),
            DirectoryInput::Ignored
        );

        directory.stream_opened(peer(A), 2);
        directory.stream_data(&peer(A), &2, &present(1, 10));
        assert_eq!(
            directory.stream_data(&peer(A), &2, &[0x00]),
            DirectoryInput::Reset(DirectoryResetReason::Malformed(
                MeshMessageError::MissingType
            ))
        );
        assert_eq!(directory.entry_count(&peer(A)), 0);
    }

    #[test]
    fn claims_order_by_later_expiry_then_lower_member() {
        let (low, high) = if peer(A) < peer(B) { (A, B) } else { (B, A) };
        let mut directory = Directory::default();
        for (member, stream, expires) in [(high, 1, 50), (low, 2, 50)] {
            directory.stream_opened(peer(member), stream);
            directory.stream_data(&peer(member), &stream, &present(1, expires));
        }
        assert_eq!(members(&directory, 1), [peer(low), peer(high)]);

        directory.stream_data(&peer(high), &1, &present(1, 60));
        assert_eq!(members(&directory, 1), [peer(high), peer(low)]);

        // Expired entries are not claims.
        let live: Vec<_> = directory
            .claims(&peer(1), 50)
            .into_iter()
            .map(|claim| claim.member.clone())
            .collect();
        assert_eq!(live, [peer(high)]);
    }
}
