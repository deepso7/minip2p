//! Relay-mesh membership (ADR 0028): a backbone connection is pending until
//! both sides' member proofs check out, and only then a member link. Node 0
//! is the agent under test; its peer, node 1, is played by hand.

mod common;

use minip2p_core::PeerId;
use minip2p_core::platform::Deadline;
use minip2p_identity::Ed25519Keypair;
use minip2p_relay_server::mesh::{
    DIRECTORY_PROTOCOL_ID, DirectoryMessage, FORWARD_PROTOCOL_ID, MEMBER_ACCEPT,
    MEMBER_PROTOCOL_ID, sign_member_proof,
};
use minip2p_relay_server::{MeshRejectionReason, RelayServerEvent, Status, StreamKey};
use minip2p_swarm::{SwarmErrorKind, SwarmEvent, SwarmRuntimeError};
use minip2p_transport::{ConnectionId, ConnectionNamespace, StreamId};

use common::mesh::{
    hop_status, member, member_open, mesh_node, proof, send_member_stream, verify_by_hand,
};
use common::{Call, Node, at, connect_request, key, peer, resets, sends_on, unlimited_rates};

/// The peer node, played by hand.
const PEER: usize = 1;

fn conn(sequence: u64) -> ConnectionId {
    ConnectionId::namespaced(ConnectionNamespace::MESH_IPV4, sequence).expect("in range")
}

fn node() -> Node {
    mesh_node(0, unlimited_rates())
}

/// `node` with the peer's backbone connection `conn_id` just established;
/// returns the commands that caused.
fn establish(node: &mut Node, conn_id: ConnectionId) -> Vec<Call> {
    node.establish(&member(PEER), conn_id);
    node.calls()
}

/// A node whose link to the peer is `conn_id`, verified, with the setup's
/// commands, events and verified links taken.
fn linked(conn_id: ConnectionId) -> Node {
    let mut node = node();
    let calls = establish(&mut node, conn_id);
    verify_by_hand(&mut node, PEER, conn_id, &calls, at(0));
    assert_eq!(
        node.events(),
        [RelayServerEvent::MeshMemberUp {
            member: member(PEER)
        }]
    );
    node.take_verified_links();
    node
}

fn closed_connections(calls: &[Call]) -> Vec<ConnectionId> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::CloseConnection { conn_id, .. } => Some(*conn_id),
            _ => None,
        })
        .collect()
}

fn opens(calls: &[Call], protocol: &str) -> Vec<StreamKey> {
    calls
        .iter()
        .filter_map(|call| match call {
            Call::Open {
                protocol_id,
                opened: Some(stream),
                ..
            } if protocol_id == protocol => Some(*stream),
            _ => None,
        })
        .collect()
}

fn rejected(reason: MeshRejectionReason) -> RelayServerEvent {
    RelayServerEvent::MeshPeerRejected {
        peer_id: member(PEER),
        reason,
    }
}

fn down() -> RelayServerEvent {
    RelayServerEvent::MeshMemberDown {
        member: member(PEER),
    }
}

/// `client` sends a CONNECT to `destination` over public connection
/// `conn`; returns the HOP stream.
fn connect(node: &mut Node, client: &PeerId, conn: u64, destination: &PeerId) -> StreamKey {
    let stream = key(conn, 1);
    node.establish(client, stream.conn_id);
    node.feed_hop(client, stream, connect_request(destination), &[]);
    stream
}

fn stream(conn_id: ConnectionId, id: u64) -> StreamKey {
    StreamKey {
        conn_id,
        stream_id: StreamId::new(id),
    }
}

fn stream_ready(node: &mut Node, stream: StreamKey, protocol: &str, local: bool) -> bool {
    node.handle_event(
        &SwarmEvent::StreamReady {
            peer_id: member(PEER),
            conn_id: stream.conn_id,
            stream_id: stream.stream_id,
            protocol_id: protocol.into(),
            initiated_locally: local,
        },
        false,
        at(0),
    )
}

#[test]
fn a_connection_both_proofs_check_out_on_becomes_a_member() {
    let mut node = node();
    let link = conn(1);
    let outbound = member_open(&establish(&mut node, link), link).expect("a member open");

    // This node's own stream carries its proof, then half-closes; the STOP
    // path never sees it.
    assert!(stream_ready(&mut node, outbound, MEMBER_PROTOCOL_ID, true));
    let calls = node.calls();
    assert_eq!(sends_on(&calls, outbound), [proof(0).to_vec()]);
    assert_eq!(common::closes(&calls), [outbound]);
    node.data(&member(PEER), outbound, &[MEMBER_ACCEPT], at(0));
    node.half_close(&member(PEER), outbound, at(0));
    assert!(node.events().is_empty(), "the peer's proof is still out");

    // The peer's proof, split across reads, is answered with the accept.
    let inbound = stream(link, 9);
    assert!(stream_ready(&mut node, inbound, MEMBER_PROTOCOL_ID, false));
    let peer_proof = proof(PEER);
    let (head, tail) = peer_proof.split_at(20);
    node.data(&member(PEER), inbound, head, at(0));
    node.data(&member(PEER), inbound, tail, at(0));
    node.half_close(&member(PEER), inbound, at(0));
    let calls = node.calls();
    assert_eq!(sends_on(&calls, inbound), [vec![MEMBER_ACCEPT]]);
    assert_eq!(common::closes(&calls), [inbound]);
    assert_eq!(opens(&calls, DIRECTORY_PROTOCOL_ID).len(), 1);
    assert_eq!(
        node.events(),
        [RelayServerEvent::MeshMemberUp {
            member: member(PEER)
        }]
    );
    assert_eq!(node.take_verified_links(), [(member(PEER), link)]);
    assert_eq!(node.next_deadline(at(0)), None, "no proof deadline left");
}

#[test]
fn a_pending_peer_gets_no_snapshot_and_neither_holds_up_nor_takes_a_connect() {
    let mut node = node();
    let alice = peer(b"membership-alice");
    node.reserve(&alice, key(10, 1));
    let link = conn(1);
    let calls = establish(&mut node, link);
    assert_eq!(opens(&calls, MEMBER_PROTOCOL_ID).len(), 1);
    assert!(
        opens(&calls, DIRECTORY_PROTOCOL_ID).is_empty(),
        "no snapshot"
    );

    // Its directory and forward streams are reset, as routine link setup.
    for (id, protocol) in [(3, DIRECTORY_PROTOCOL_ID), (5, FORWARD_PROTOCOL_ID)] {
        let mesh_stream = stream(link, id);
        assert!(stream_ready(&mut node, mesh_stream, protocol, false));
        assert_eq!(resets(&node.calls()), [mesh_stream]);
        assert!(node.owns_stream(mesh_stream), "claimed until it closes");
    }
    assert!(node.events().is_empty());

    // A CONNECT to a peer reserved nowhere is refused at once: a pending
    // connection is no directory member to wait on, nor a forward target.
    let bob = peer(b"membership-bob");
    let hop = connect(&mut node, &bob, 20, &peer(b"membership-nobody"));
    let calls = node.calls();
    assert!(opens(&calls, FORWARD_PROTOCOL_ID).is_empty());
    assert_eq!(hop_status(&calls, hop).0, Some(Status::NoReservation));
}

#[test]
fn a_malformed_or_foreign_proof_closes_the_connection() {
    let other_identity = Ed25519Keypair::from_secret_key_bytes([9; 32]);
    let mut long = proof(PEER).to_vec();
    long.push(0);
    let cases: [(&str, Vec<u8>, MeshRejectionReason); 5] = [
        (
            "short",
            proof(PEER)[..63].to_vec(),
            MeshRejectionReason::MalformedProof,
        ),
        ("early EOF", Vec::new(), MeshRejectionReason::MalformedProof),
        ("trailing byte", long, MeshRejectionReason::MalformedProof),
        (
            "another member's",
            proof(2).to_vec(),
            MeshRejectionReason::InvalidProof,
        ),
        (
            "another public identity's",
            sign_member_proof(&other_identity, &member(PEER)).to_vec(),
            MeshRejectionReason::InvalidProof,
        ),
    ];
    for (case, message, reason) in cases {
        let mut node = node();
        let link = conn(1);
        establish(&mut node, link);
        send_member_stream(&mut node, PEER, stream(link, 9), &message, at(0));
        assert_eq!(closed_connections(&node.calls()), [link], "{case}");
        assert_eq!(node.events(), [rejected(reason)], "{case}");
        assert_eq!(node.next_deadline(at(0)), None, "{case}");
    }
}

#[test]
fn a_malformed_answer_to_this_nodes_proof_closes_the_connection() {
    for answer in [&[][..], &[0], &[MEMBER_ACCEPT, MEMBER_ACCEPT]] {
        let mut node = node();
        let link = conn(1);
        let outbound = member_open(&establish(&mut node, link), link).expect("a member open");
        stream_ready(&mut node, outbound, MEMBER_PROTOCOL_ID, true);
        node.calls();
        if !answer.is_empty() {
            node.data(&member(PEER), outbound, answer, at(0));
        }
        node.half_close(&member(PEER), outbound, at(0));
        assert_eq!(closed_connections(&node.calls()), [link], "{answer:?}");
        assert_eq!(
            node.events(),
            [rejected(MeshRejectionReason::MalformedAccept)],
            "{answer:?}"
        );
    }
}

#[test]
fn a_second_inbound_member_stream_rejects_the_connection() {
    let mut node = node();
    let link = conn(1);
    establish(&mut node, link);
    stream_ready(&mut node, stream(link, 9), MEMBER_PROTOCOL_ID, false);
    assert!(stream_ready(
        &mut node,
        stream(link, 11),
        MEMBER_PROTOCOL_ID,
        false
    ));
    assert_eq!(closed_connections(&node.calls()), [link]);
    assert_eq!(
        node.events(),
        [rejected(MeshRejectionReason::DuplicateProof)]
    );
}

#[test]
fn dropped_member_streams_leave_the_connection_to_its_five_second_deadline() {
    let mut node = node();
    let link = conn(1);
    let outbound = member_open(&establish(&mut node, link), link).expect("a member open");
    assert_eq!(
        node.next_deadline(at(0)),
        Some(Deadline::from_millis(5_000))
    );

    // A reset before EOF, on either side, judges nothing.
    let inbound = stream(link, 9);
    stream_ready(&mut node, inbound, MEMBER_PROTOCOL_ID, false);
    node.data(&member(PEER), inbound, &proof(PEER)[..10], at(0));
    assert!(node.stream_closed(&member(PEER), inbound, at(0)));
    let failed = SwarmEvent::Error(SwarmRuntimeError {
        kind: SwarmErrorKind::OpenStreamFailed,
        peer_id: Some(member(PEER)),
        conn_id: Some(link),
        stream_id: Some(outbound.stream_id),
        detail: "stream reset".into(),
    });
    assert!(node.handle_event(&failed, false, at(0)));
    node.handle_tick(at(4_999));
    assert!(closed_connections(&node.calls()).is_empty());
    assert!(node.events().is_empty());

    // With no other traffic, the deadline alone closes it.
    node.handle_tick(at(5_000));
    assert_eq!(closed_connections(&node.calls()), [link]);
    assert_eq!(node.events(), [rejected(MeshRejectionReason::TimedOut)]);
    assert_eq!(node.next_deadline(at(5_000)), None);
}

#[test]
fn an_oversized_message_is_judged_only_at_its_half_close() {
    let mut long = proof(PEER).to_vec();
    long.push(0);
    let mut node = node();
    let link = conn(1);
    let outbound = member_open(&establish(&mut node, link), link).expect("a member open");
    stream_ready(&mut node, outbound, MEMBER_PROTOCOL_ID, true);
    node.data(
        &member(PEER),
        outbound,
        &[MEMBER_ACCEPT, MEMBER_ACCEPT],
        at(0),
    );
    let inbound = stream(link, 9);
    stream_ready(&mut node, inbound, MEMBER_PROTOCOL_ID, false);
    node.data(&member(PEER), inbound, &long, at(0));
    // Reset before EOF, both are dropped; the deadline is what closes it.
    node.stream_closed(&member(PEER), outbound, at(0));
    node.stream_closed(&member(PEER), inbound, at(0));
    assert!(closed_connections(&node.calls()).is_empty());
    assert!(node.events().is_empty());
    node.handle_tick(at(5_000));
    assert_eq!(node.events(), [rejected(MeshRejectionReason::TimedOut)]);
}

#[test]
fn an_accept_that_did_not_go_out_never_makes_a_member() {
    for accept_first in [true, false] {
        let mut node = node();
        let link = conn(1);
        let outbound = member_open(&establish(&mut node, link), link).expect("a member open");
        let inbound = stream(link, 9);
        node.swarm.failing_sends.insert(inbound);
        let accept = |node: &mut Node| {
            stream_ready(node, outbound, MEMBER_PROTOCOL_ID, true);
            node.data(&member(PEER), outbound, &[MEMBER_ACCEPT], at(0));
            node.half_close(&member(PEER), outbound, at(0));
        };
        if accept_first {
            accept(&mut node);
        }
        send_member_stream(&mut node, PEER, inbound, &proof(PEER), at(0));
        if !accept_first {
            accept(&mut node);
        }
        let calls = node.calls();
        assert!(
            opens(&calls, DIRECTORY_PROTOCOL_ID).is_empty(),
            "{accept_first}"
        );
        assert!(
            !node
                .events()
                .iter()
                .any(|event| matches!(event, RelayServerEvent::MeshMemberUp { .. })),
            "{accept_first}"
        );
        assert!(node.take_verified_links().is_empty());
    }
}

#[test]
fn a_directory_stream_the_pending_peer_resets_reopens_on_the_link() {
    let (mut node, first) = node_with_directory(conn(1));
    // The peer, still pending on its side, reset it.
    node.stream_closed(&member(PEER), first, at(10));
    node.handle_tick(at(1_009));
    assert!(opens(&node.calls(), DIRECTORY_PROTOCOL_ID).is_empty());
    node.handle_tick(at(1_010));
    let reopened = opens(&node.calls(), DIRECTORY_PROTOCOL_ID);
    assert_eq!(
        reopened
            .iter()
            .map(|stream| stream.conn_id)
            .collect::<Vec<_>>(),
        [conn(1)]
    );
}

/// A verified link and the directory stream it opened.
#[expect(clippy::panic, reason = "a setup that went wrong fails the test")]
fn node_with_directory(link: ConnectionId) -> (Node, StreamKey) {
    let mut node = node();
    let calls = establish(&mut node, link);
    let calls = verify_by_hand(&mut node, PEER, link, &calls, at(0));
    let directory = opens(&calls, DIRECTORY_PROTOCOL_ID);
    let [directory] = directory[..] else {
        panic!("one directory open: {calls:?}");
    };
    node.events();
    (node, directory)
}

#[test]
fn a_verified_replacement_emits_no_down_or_second_up() {
    let mut node = linked(conn(1));
    node.calls();
    node.replace(&member(PEER), conn(1), conn(2), false, 1);
    let calls = node.calls();
    assert_eq!(opens(&calls, MEMBER_PROTOCOL_ID).len(), 1);
    assert!(opens(&calls, DIRECTORY_PROTOCOL_ID).is_empty());
    let calls = verify_by_hand(&mut node, PEER, conn(2), &calls, at(1));
    assert_eq!(
        opens(&calls, DIRECTORY_PROTOCOL_ID)
            .iter()
            .map(|stream| stream.conn_id)
            .collect::<Vec<_>>(),
        [conn(2)]
    );
    assert!(node.events().is_empty(), "no Down or Up for a replacement");
    assert_eq!(node.take_verified_links(), [(member(PEER), conn(2))]);
}

/// A linked node whose peer never synced, so a CONNECT to a peer reserved
/// nowhere waits on it; returns the CONNECT's HOP stream.
fn waiting_connect(node: &mut Node) -> StreamKey {
    let hop = connect(
        node,
        &peer(b"membership-bob"),
        20,
        &peer(b"membership-nobody"),
    );
    assert_eq!(hop_status(&node.calls(), hop).0, None, "waiting");
    hop
}

#[test]
fn a_replacement_that_fails_its_proof_ends_the_member() {
    let mut node = linked(conn(1));
    let hop = waiting_connect(&mut node);
    node.replace(&member(PEER), conn(1), conn(2), false, 1);
    assert_eq!(hop_status(&node.calls(), hop).0, None, "still waiting");
    send_member_stream(&mut node, PEER, stream(conn(2), 9), &proof(2), at(1));
    let calls = node.calls();
    assert_eq!(closed_connections(&calls), [conn(2)]);
    assert_eq!(hop_status(&calls, hop).0, Some(Status::NoReservation));
    assert_eq!(
        node.events()
            .into_iter()
            .filter(|event| !matches!(event, RelayServerEvent::CircuitDenied { .. }))
            .collect::<Vec<_>>(),
        [rejected(MeshRejectionReason::InvalidProof), down()]
    );
}

#[test]
fn a_replacement_replaced_again_hands_on_the_member_until_it_times_out() {
    let mut node = linked(conn(1));
    let hop = waiting_connect(&mut node);
    node.replace(&member(PEER), conn(1), conn(2), false, 1);
    // The simultaneous-dial tiebreak replaces the pending connection.
    node.replace(&member(PEER), conn(2), conn(3), false, 2);
    assert!(node.events().is_empty());
    node.handle_tick(at(5_001));
    assert_eq!(
        hop_status(&node.calls(), hop).0,
        None,
        "conn(2)'s deadline went with it"
    );
    node.handle_tick(at(5_002));
    let calls = node.calls();
    assert_eq!(closed_connections(&calls), [conn(3)]);
    assert_eq!(hop_status(&calls, hop).0, Some(Status::NoReservation));
    let events = node.events();
    assert!(events.contains(&rejected(MeshRejectionReason::TimedOut)));
    assert!(events.contains(&down()));
}

#[test]
fn a_late_deadline_or_bad_proof_for_an_already_replaced_connection_keeps_the_member() {
    let mut node = linked(conn(1));
    let hop = waiting_connect(&mut node);
    node.replace(&member(PEER), conn(1), conn(2), false, 0);
    node.calls();
    // The swarm replaced conn(2) in this poll; its event is still queued.
    node.swarm.connect(&member(PEER), conn(3));
    send_member_stream(&mut node, PEER, stream(conn(2), 9), &proof(2), at(1));
    node.handle_tick(at(5_000));
    assert!(closed_connections(&node.calls()).is_empty());
    assert!(node.events().is_empty(), "neither rejected nor down");

    // The replacement inherits the member and verifies on its own.
    node.replace(&member(PEER), conn(2), conn(3), false, 5_000);
    let calls = node.calls();
    verify_by_hand(&mut node, PEER, conn(3), &calls, at(5_000));
    assert!(node.events().is_empty(), "no Up: the member never left");
    assert_eq!(node.take_verified_links(), [(member(PEER), conn(3))]);
    assert_eq!(
        hop_status(&node.calls(), hop).0,
        None,
        "waits for the snapshot"
    );
}

#[test]
fn opens_meant_for_a_replaced_connection_are_not_made_on_the_replacement() {
    // Member: the swarm is already on conn(2) when conn(1) comes up.
    let mut node = node();
    node.swarm.connect(&member(PEER), conn(2));
    let established = SwarmEvent::ConnectionEstablished {
        peer_id: member(PEER),
        conn_id: conn(1),
    };
    node.agent
        .handle_event(&mut node.swarm, &established, false, at(0));
    assert!(opens(&node.calls(), MEMBER_PROTOCOL_ID).is_empty());
    node.replace(&member(PEER), conn(1), conn(2), false, 0);
    let opened = opens(&node.calls(), MEMBER_PROTOCOL_ID);
    assert_eq!(
        opened.iter().map(|s| s.conn_id).collect::<Vec<_>>(),
        [conn(2)]
    );

    // Directory: a reopen due after the swarm replaced the link.
    let (mut node, directory) = node_with_directory(conn(1));
    node.stream_closed(&member(PEER), directory, at(10));
    node.swarm.connect(&member(PEER), conn(2));
    node.handle_tick(at(1_010));
    assert!(opens(&node.calls(), DIRECTORY_PROTOCOL_ID).is_empty());

    // Forward: a claim on a link the swarm replaced is a failed claim.
    let (mut node, _) = node_with_directory(conn(1));
    let alice = peer(b"membership-alice");
    let inbound = stream(conn(1), 13);
    stream_ready(&mut node, inbound, DIRECTORY_PROTOCOL_ID, false);
    let mut snapshot = DirectoryMessage::Present {
        peer: alice,
        expires_unix: u64::MAX,
    }
    .encode_frame();
    snapshot.extend(DirectoryMessage::Synced.encode_frame());
    node.data(&member(PEER), inbound, &snapshot, at(0));
    node.calls();
    node.swarm.connect(&member(PEER), conn(2));
    let hop = connect(&mut node, &peer(b"membership-bob"), 20, &alice);
    let calls = node.calls();
    assert!(opens(&calls, FORWARD_PROTOCOL_ID).is_empty(), "{calls:?}");
    assert_eq!(hop_status(&calls, hop).0, Some(Status::ConnectionFailed));
}

#[test]
fn a_mesh_key_that_is_not_the_relays_own_is_refused() {
    let mut config = unlimited_rates();
    config.mesh = Some(minip2p_relay_server::mesh::MeshConfig::new(
        &Ed25519Keypair::from_secret_key_bytes([9; 32]),
        &member(0),
    ));
    let error = minip2p_relay_server::RelayServerAgent::new(common::mesh::relay_peer(), config)
        .err()
        .expect("refused");
    assert_eq!(error.field, "mesh.public_key");
}
