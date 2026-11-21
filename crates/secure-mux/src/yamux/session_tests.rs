use super::*;
use crate::yamux::{KEEPALIVE_ACK_TIMEOUT_MS, KEEPALIVE_HANDOFF_TIMEOUT_MS, KEEPALIVE_INTERVAL_MS};
use minip2p_core::platform::{Deadline, Now};

fn outbound(session: &mut YamuxSession) -> Vec<u8> {
    session.poll_frame().expect("outbound Yamux frame")
}

fn decode(bytes: &[u8]) -> Frame {
    let mut decoder = FrameDecoder::new(u32::MAX);
    decoder.push(bytes);
    decoder.next_frame().unwrap().unwrap()
}

fn config() -> YamuxConfig {
    YamuxConfig {
        max_streams: 8,
        max_buffered_send: DEFAULT_RECEIVE_WINDOW as usize,
        max_total_buffered_send: DEFAULT_RECEIVE_WINDOW as usize * 2,
        control_stream_reserve: 0,
        ..YamuxConfig::default()
    }
}

#[test]
fn clients_use_odd_ids_and_servers_use_even_ids() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let mut server = YamuxSession::new(YamuxRole::Server);
    assert_eq!(client.open_stream().unwrap(), 1);
    assert_eq!(client.open_stream().unwrap(), 3);
    assert_eq!(server.open_stream().unwrap(), 2);
    assert_eq!(server.open_stream().unwrap(), 4);
}

#[test]
fn remote_stream_ids_exclude_the_reserved_session_id() {
    let client = YamuxSession::new(YamuxRole::Client);
    let server = YamuxSession::new(YamuxRole::Server);

    assert!(!client.valid_remote_stream_id(0));
    assert!(client.valid_remote_stream_id(2));
    assert!(!client.valid_remote_stream_id(1));
    assert!(!server.valid_remote_stream_id(0));
    assert!(server.valid_remote_stream_id(1));
    assert!(!server.valid_remote_stream_id(2));
}

#[test]
fn syn_and_ack_piggyback_on_first_data_frames() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let mut server = YamuxSession::new(YamuxRole::Server);
    let stream = client.open_stream().unwrap();
    client.send(stream, Bytes::from(b"hello".to_vec())).unwrap();
    let opening = outbound(&mut client);
    assert_eq!(decode(&opening).flags(), FLAG_SYN);
    server.handle_data(&opening).unwrap();
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::IncomingStream { stream })
    );
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::Data {
            stream,
            data: b"hello".to_vec()
        })
    );
    server.send(stream, Bytes::from(b"world".to_vec())).unwrap();
    let response = outbound(&mut server);
    assert_eq!(decode(&response).flags(), FLAG_ACK);
    client.handle_data(&response).unwrap();
    assert!(client.is_acknowledged(stream).unwrap());
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::Data {
            stream,
            data: b"world".to_vec()
        })
    );
}

#[test]
fn server_opened_stream_completes_a_bidirectional_lifecycle() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let mut server = YamuxSession::new(YamuxRole::Server);
    let stream = server.open_stream().unwrap();
    server
        .send(stream, Bytes::from(b"request".to_vec()))
        .unwrap();
    client.handle_data(&outbound(&mut server)).unwrap();
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::IncomingStream { stream })
    );
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::Data {
            stream,
            data: b"request".to_vec()
        })
    );

    client
        .send(stream, Bytes::from(b"response".to_vec()))
        .unwrap();
    server.handle_data(&outbound(&mut client)).unwrap();
    assert!(server.is_acknowledged(stream).unwrap());
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::Data {
            stream,
            data: b"response".to_vec()
        })
    );

    server.close_write(stream).unwrap();
    client.handle_data(&outbound(&mut server)).unwrap();
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::RemoteWriteClosed { stream })
    );
    client.close_write(stream).unwrap();
    server.handle_data(&outbound(&mut client)).unwrap();
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::StreamClosed { stream })
    );
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::RemoteWriteClosed { stream })
    );
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::StreamClosed { stream })
    );
}

#[test]
fn idle_open_and_accept_emit_standalone_control_frames() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let mut server = YamuxSession::new(YamuxRole::Server);
    let stream = client.open_stream().unwrap();
    let syn = outbound(&mut client);
    let frame = decode(&syn);
    assert_eq!(frame.frame_type(), FrameType::WindowUpdate);
    assert_eq!(frame.flags(), FLAG_SYN);
    server.handle_data(&syn).unwrap();
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::IncomingStream { stream })
    );
    let ack = outbound(&mut server);
    assert_eq!(decode(&ack).flags(), FLAG_ACK);
    client.handle_data(&ack).unwrap();
    assert!(client.is_acknowledged(stream).unwrap());
}

#[test]
fn accepted_bytes_count_until_pulled_and_queue_past_the_window() {
    let mut limits = config();
    limits.max_buffered_send *= 2;
    limits.max_frame_len = u32::MAX;
    let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let stream = client.open_stream().unwrap();
    let data = Bytes::from(alloc::vec![7; DEFAULT_RECEIVE_WINDOW as usize + 5]);
    client.send(stream, data).unwrap();
    assert_eq!(
        client.total_buffered_send(),
        DEFAULT_RECEIVE_WINDOW as usize + 5
    );
    let first = outbound(&mut client);
    assert_eq!(
        decode(&first).payload().len(),
        DEFAULT_RECEIVE_WINDOW as usize
    );
    assert_eq!(client.total_buffered_send(), 5);
    assert_eq!(client.poll_frame(), None, "no credit, no frame");

    let update = Frame::window_update(stream, FLAG_ACK, 5).unwrap().encode();
    client.handle_data(&update).unwrap();
    assert_eq!(decode(&outbound(&mut client)).payload(), &[7; 5]);
    assert_eq!(client.total_buffered_send(), 0);
}

#[test]
fn partial_windows_frame_queued_bytes_in_order() {
    let mut limits = config();
    limits.max_frame_len = 4;
    let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let stream = client.open_stream().unwrap();
    client.streams.get_mut(&stream).unwrap().send_window = 10;
    client
        .send(stream, Bytes::from(b"abcdefghijkl".to_vec()))
        .unwrap();
    client
        .send(stream, Bytes::from(b"mnopqrstu".to_vec()))
        .unwrap();
    let payloads = |client: &mut YamuxSession| {
        core::iter::from_fn(|| client.poll_output())
            .map(|output| match output {
                YamuxOutput::Outbound(bytes) => decode(&bytes).payload().to_vec(),
                output => panic!("expected outbound bytes, got {output:?}"),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(payloads(&mut client), [&b"abcd"[..], b"efgh", b"ij"]);

    for (credit, expected) in [
        (1, &[&b"k"[..]][..]),
        (3, &[b"l", b"mn"]),
        (9, &[b"opqr", b"stu"]),
    ] {
        let update = Frame::window_update(stream, 0, credit).unwrap().encode();
        client.handle_data(&update).unwrap();
        assert_eq!(payloads(&mut client), expected);
    }
    assert_eq!(client.total_buffered_send(), 0);
}

#[test]
fn data_frames_rotate_across_sendable_streams() {
    let mut limits = config();
    limits.max_frame_len = 2;
    let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let [a, b, c, idle] = [(); 4].map(|_| client.open_stream().unwrap());
    client.send(a, Bytes::from(b"a1a2a3".to_vec())).unwrap();
    client.send(c, Bytes::from(b"c1".to_vec())).unwrap();
    let next = |client: &mut YamuxSession| {
        let frame = decode(&outbound(client));
        (frame.stream_id(), frame.payload().to_vec())
    };
    assert_eq!(next(&mut client), (b, Vec::new()));
    assert_eq!(next(&mut client), (idle, Vec::new()));
    assert_eq!(next(&mut client), (a, b"a1".to_vec()));
    client.send(b, Bytes::from(b"b1b2".to_vec())).unwrap();
    assert_eq!(next(&mut client), (b, b"b1".to_vec()));
    assert_eq!(next(&mut client), (c, b"c1".to_vec()));
    assert_eq!(next(&mut client), (a, b"a2".to_vec()));
    assert_eq!(next(&mut client), (b, b"b2".to_vec()));
    assert_eq!(next(&mut client), (a, b"a3".to_vec()));
    assert_eq!(client.poll_frame(), None);
}

#[test]
fn default_data_frames_carry_at_most_16_kib() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let stream = client.open_stream().unwrap();
    client
        .send(stream, Bytes::from(alloc::vec![7; 40 * 1024]))
        .unwrap();
    let lens: Vec<_> = core::iter::from_fn(|| client.poll_frame())
        .map(|frame| decode(&frame).payload().len())
        .collect();
    assert_eq!(lens, [16 * 1024, 16 * 1024, 8 * 1024]);
}

#[test]
fn default_frames_interleave_backlogged_streams() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let [a, b] = [(); 2].map(|_| client.open_stream().unwrap());
    for stream in [a, b] {
        client
            .send(stream, Bytes::from(alloc::vec![1; 64 * 1024]))
            .unwrap();
    }
    let order: Vec<_> = core::iter::from_fn(|| client.poll_frame())
        .map(|frame| decode(&frame).stream_id())
        .collect();
    assert_eq!(order, [a, b].repeat(4));
}

#[test]
fn the_highest_stream_id_does_not_starve_the_rotation() {
    let mut limits = config();
    limits.max_frame_len = 2;
    let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
    for stream in [1, u32::MAX] {
        let syn = Frame::window_update(stream, FLAG_SYN, 0).unwrap().encode();
        server.handle_data(&syn).unwrap();
        server.send(stream, Bytes::from(b"xxxx".to_vec())).unwrap();
    }
    let order: Vec<_> = core::iter::from_fn(|| server.poll_frame())
        .map(|frame| decode(&frame).stream_id())
        .collect();
    assert_eq!(order, [1, u32::MAX, 1, u32::MAX]);
}

#[test]
fn queued_chunks_retain_at_most_twice_their_unsent_bytes() {
    let mut client = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
    let stream = client.open_stream().unwrap();
    let source = Bytes::from(alloc::vec![1; 100]);
    let retains_source = |client: &YamuxSession| {
        client.streams[&stream].send_buffer.iter().any(|chunk| {
            chunk.bytes.as_ptr() >= source.as_ptr()
                && chunk.bytes.as_ptr() < source.as_ptr().wrapping_add(100)
        })
    };
    client.streams.get_mut(&stream).unwrap().send_window = 40;
    client.send(stream, source.clone()).unwrap();
    while client.poll_frame().is_some() {}
    assert_eq!(client.total_buffered_send(), 60);
    assert!(retains_source(&client), "a tail of 60/100 stays a slice");

    let update = Frame::window_update(stream, 0, 20).unwrap().encode();
    client.handle_data(&update).unwrap();
    while client.poll_frame().is_some() {}
    assert_eq!(client.total_buffered_send(), 40);
    assert!(
        !retains_source(&client),
        "a tail under half its counted length is copied out"
    );
}

#[test]
fn a_write_past_the_caps_returns_the_exact_unsent_suffix() {
    let mut limits = config();
    limits.max_buffered_send = 4;
    limits.max_total_buffered_send = 6;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let first = session.open_stream().unwrap();
    let second = session.open_stream().unwrap();

    let unsent = |result| match result {
        Err(YamuxError::Full { unsent, .. }) => unsent,
        other => panic!("expected Full, got {other:?}"),
    };
    assert_eq!(
        unsent(session.send(first, Bytes::from_static(b"abcde"))),
        &b"e"[..]
    );
    assert_eq!(session.total_buffered_send(), 4);
    assert_eq!(
        unsent(session.send(second, Bytes::from_static(b"xyz"))),
        &b"z"[..]
    );
    assert_eq!(
        unsent(session.send(second, Bytes::from_static(b"!"))),
        &b"!"[..],
        "nothing fits: the whole payload comes back"
    );
    assert_eq!(session.total_buffered_send(), 6);
}

#[test]
fn resending_tails_after_writable_reproduces_the_byte_stream() {
    let mut limits = config();
    limits.max_buffered_send = 8;
    limits.max_frame_len = 3;
    let mut client = YamuxSession::with_config(YamuxRole::Client, limits.clone()).unwrap();
    let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
    let stream = client.open_stream().unwrap();
    let payload: Vec<u8> = (0..100).collect();
    let mut pending = Some(Bytes::from(payload.clone()));
    let mut received = Vec::new();
    let mut writable_count = 0;
    while pending.is_some() || client.has_frames() {
        if let Some(data) = pending.take() {
            match client.send(stream, data) {
                Ok(()) => {}
                Err(YamuxError::Full { unsent, .. }) => pending = Some(unsent),
                Err(error) => panic!("{error}"),
            }
        }
        while let Some(frame) = client.poll_frame() {
            server.handle_data(&frame).unwrap();
        }
        while let Some(event) = client.poll_event() {
            assert_eq!(event, YamuxOutput::Writable { stream });
            writable_count += 1;
        }
        while let Some(output) = server.poll_output() {
            match output {
                YamuxOutput::Data { data, .. } => received.extend(data),
                YamuxOutput::Outbound(frame) => client.handle_data(&frame).unwrap(),
                _ => {}
            }
        }
    }
    assert_eq!(received, payload);
    assert!(writable_count > 0);
}

#[test]
fn writable_fires_once_per_full_and_for_shared_cap_blocks() {
    let mut limits = config();
    limits.max_buffered_send = 8;
    limits.max_total_buffered_send = 8;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let busy = session.open_stream().unwrap();
    let starved = session.open_stream().unwrap();
    session.send(busy, Bytes::from(alloc::vec![1; 8])).unwrap();
    assert!(matches!(
        session.send(starved, Bytes::from_static(b"x")),
        Err(YamuxError::Full { .. })
    ));
    assert!(matches!(
        session.send(busy, Bytes::from_static(b"y")),
        Err(YamuxError::Full { .. })
    ));
    while session.poll_frame().is_some() {}
    let mut woken = Vec::new();
    while let Some(event) = session.poll_event() {
        if let YamuxOutput::Writable { stream } = event {
            woken.push(stream);
        }
    }
    woken.sort_unstable();
    assert_eq!(woken, [busy, starved]);

    session.send(busy, Bytes::from_static(b"z")).unwrap();
    while session.poll_frame().is_some() {}
    assert_eq!(
        session.poll_event(),
        None,
        "no second Writable without a Full"
    );
}

#[test]
fn control_streams_queue_into_the_reserve_application_streams_cannot_fill() {
    let mut limits = config();
    limits.max_buffered_send = 8;
    limits.max_total_buffered_send = 12;
    limits.control_stream_reserve = 4;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let app = session.open_stream().unwrap();
    let other_app = session.open_stream().unwrap();
    let control = session.open_stream().unwrap();
    session.set_control(control, true);

    session.send(app, Bytes::from(alloc::vec![1; 8])).unwrap();
    assert!(matches!(
        session.send(other_app, Bytes::from_static(b"xyz")),
        Err(YamuxError::Full { unsent, .. }) if unsent == b"xyz"[..]
    ));
    session
        .send(control, Bytes::from_static(b"ping"))
        .expect("the reserve holds a control write");
    assert_eq!(session.total_buffered_send(), 12);

    session.set_control(control, false);
    while session.poll_frame().is_some() {}
    assert!(matches!(
        session.send(control, Bytes::from(alloc::vec![2; 9])),
        Err(YamuxError::Full { unsent, .. }) if unsent.len() == 1
    ));
}

#[test]
fn a_full_control_stream_wakes_once_the_reserve_frees_even_when_it_is_small() {
    let mut limits = config();
    limits.max_buffered_send = 8;
    limits.max_total_buffered_send = 12;
    limits.control_stream_reserve = 2;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let apps = [
        session.open_stream().unwrap(),
        session.open_stream().unwrap(),
    ];
    let control = session.open_stream().unwrap();
    session.set_control(control, true);

    for app in apps {
        session.streams.get_mut(&app).unwrap().send_window = 0;
        match session.send(app, Bytes::from(alloc::vec![1; 8])) {
            Ok(()) | Err(YamuxError::Full { .. }) => {}
            Err(error) => panic!("{error}"),
        }
    }
    assert_eq!(session.total_buffered_send(), 10);
    assert!(matches!(
        session.send(control, Bytes::from_static(b"ping")),
        Err(YamuxError::Full { unsent, .. }) if unsent.len() == 2
    ));

    while session.poll_frame().is_some() {}
    let events: Vec<_> = core::iter::from_fn(|| session.poll_event()).collect();
    assert!(
        events.contains(&YamuxOutput::Writable { stream: control }),
        "{events:?}"
    );
}

#[test]
fn a_config_whose_reserve_leaves_application_streams_nothing_is_rejected() {
    let mut limits = config();
    limits.max_total_buffered_send = 8;
    limits.control_stream_reserve = 8;
    assert!(matches!(
        YamuxSession::with_config(YamuxRole::Client, limits),
        Err(YamuxError::InvalidConfig(_))
    ));
}

#[test]
fn a_reset_that_frees_the_shared_cap_wakes_blocked_streams() {
    let mut limits = config();
    limits.max_buffered_send = 8;
    limits.max_total_buffered_send = 8;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let hog = session.open_stream().unwrap();
    let blocked = session.open_stream().unwrap();
    session.streams.get_mut(&hog).unwrap().send_window = 0;
    session.send(hog, Bytes::from(alloc::vec![1; 8])).unwrap();
    assert!(matches!(
        session.send(blocked, Bytes::from_static(b"x")),
        Err(YamuxError::Full { .. })
    ));

    session.reset(hog).unwrap();
    let events: Vec<_> = core::iter::from_fn(|| session.poll_event()).collect();
    assert!(
        events.contains(&YamuxOutput::Writable { stream: blocked }),
        "freeing the shared cap must wake the blocked stream: {events:?}"
    );
}

#[test]
fn a_writable_already_queued_is_dropped_when_the_write_side_closes() {
    let mut limits = config();
    limits.max_buffered_send = 4;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let stream = session.open_stream().unwrap();
    assert!(matches!(
        session.send(stream, Bytes::from_static(b"abcdef")),
        Err(YamuxError::Full { .. })
    ));
    while session.poll_frame().is_some() {}
    session.close_write(stream).unwrap();
    assert_eq!(session.poll_event(), None);
}

#[test]
fn a_writable_already_queued_is_dropped_when_the_session_goes_away() {
    let mut limits = config();
    limits.max_buffered_send = 4;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let stream = session.open_stream().unwrap();
    assert!(matches!(
        session.send(stream, Bytes::from_static(b"abcdef")),
        Err(YamuxError::Full { .. })
    ));
    while session.poll_frame().is_some() {}
    session.go_away(0);
    let events: Vec<_> = core::iter::from_fn(|| session.poll_event()).collect();
    assert_eq!(events, [YamuxOutput::StreamClosed { stream }]);
}

#[test]
fn local_resets_do_not_spend_the_peer_control_reserve() {
    let mut limits = config();
    limits.max_pending_control = 1;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    for _ in 0..3 {
        let stream = session.open_stream().unwrap();
        assert!(session.poll_frame().is_some(), "announce the stream");
        session.reset(stream).unwrap();
    }
    session
        .handle_data(&Frame::ping(FLAG_SYN, 1).unwrap().encode())
        .expect("one peer ping fits the reserve");
}

#[test]
fn writable_never_fires_after_the_write_side_ends() {
    let mut limits = config();
    limits.max_buffered_send = 4;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let closed = session.open_stream().unwrap();
    let reset = session.open_stream().unwrap();
    for stream in [closed, reset] {
        assert!(matches!(
            session.send(stream, Bytes::from_static(b"abcdef")),
            Err(YamuxError::Full { .. })
        ));
    }
    session.close_write(closed).unwrap();
    assert!(matches!(
        session.send(closed, Bytes::from_static(b"late")),
        Err(YamuxError::StreamWriteClosed(_))
    ));
    session.reset(reset).unwrap();
    while session.poll_frame().is_some() {}
    while let Some(event) = session.poll_event() {
        assert!(
            !matches!(event, YamuxOutput::Writable { .. }),
            "unexpected {event:?}"
        );
    }
}

#[test]
fn resets_of_peer_opened_streams_spend_the_control_reserve() {
    let mut limits = config();
    limits.max_pending_control = 2;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let mut reset_inbound = |stream: u32| {
        session
            .handle_data(&Frame::window_update(stream, FLAG_SYN, 0).unwrap().encode())
            .unwrap();
        session.reset(stream)
    };
    reset_inbound(2).unwrap();
    reset_inbound(4).unwrap();
    assert!(matches!(
        reset_inbound(6),
        Err(YamuxError::ControlReserveExhausted { limit: 2 })
    ));
    let frames: Vec<_> = core::iter::from_fn(|| session.poll_frame()).collect();
    assert_eq!(frames.len(), 1, "only the protocol GoAway remains");
    assert_eq!(decode(&frames[0]).frame_type(), FrameType::GoAway);
}

#[test]
fn a_peer_flooding_pings_cannot_grow_control_past_the_reserve() {
    let mut limits = config();
    limits.max_pending_control = 4;
    let mut session = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    let ping = Frame::ping(FLAG_SYN, 1).unwrap().encode();
    for _ in 0..4 {
        session.handle_data(&ping).unwrap();
    }
    assert!(matches!(
        session.handle_data(&ping),
        Err(YamuxError::ControlReserveExhausted { limit: 4 })
    ));
    let frames: Vec<_> = core::iter::from_fn(|| session.poll_frame()).collect();
    assert_eq!(frames.len(), 1, "only the protocol GoAway remains");
    assert_eq!(decode(&frames[0]).frame_type(), FrameType::GoAway);
}

#[test]
fn inbound_events_do_not_wait_behind_unpulled_frames() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let mut server = YamuxSession::new(YamuxRole::Server);
    let stream = client.open_stream().unwrap();
    client.send(stream, Bytes::from_static(b"hi")).unwrap();
    server.handle_data(&outbound(&mut client)).unwrap();
    server
        .send(stream, Bytes::from(alloc::vec![0; 1000]))
        .unwrap();
    server
        .handle_data(&Frame::ping(FLAG_SYN, 7).unwrap().encode())
        .unwrap();
    assert_eq!(
        server.poll_event(),
        Some(YamuxOutput::IncomingStream { stream })
    );
    assert!(matches!(
        server.poll_event(),
        Some(YamuxOutput::Data { .. })
    ));
    assert!(server.has_frames());
}

#[test]
fn close_waits_for_buffered_data_and_reset_is_immediate() {
    let mut session = YamuxSession::with_config(YamuxRole::Client, config()).unwrap();
    let stream = session.open_stream().unwrap();
    session.streams.get_mut(&stream).unwrap().send_window = 0;
    session.send(stream, Bytes::from_static(b"queued")).unwrap();
    session.close_write(stream).unwrap();
    assert_eq!(session.streams[&stream].write, WriteSide::FinPending);
    assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_SYN);
    assert_eq!(session.poll_frame(), None);
    session
        .handle_data(&Frame::window_update(stream, FLAG_ACK, 6).unwrap().encode())
        .unwrap();
    let data = decode(&outbound(&mut session));
    assert_eq!(data.payload(), b"queued");
    assert_eq!(data.flags(), FLAG_FIN, "FIN rides on the last data frame");

    let reset_stream = session.open_stream().unwrap();
    assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_SYN);
    session.reset(reset_stream).unwrap();
    assert_eq!(
        session.poll_output(),
        Some(YamuxOutput::StreamClosed {
            stream: reset_stream
        })
    );
    assert_eq!(decode(&outbound(&mut session)).flags(), FLAG_RST);
}

/// A server whose peer opened stream 1 and sent `len` bytes on it.
fn server_with_delivered(limits: YamuxConfig, len: usize, flags: u16) -> YamuxSession {
    let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
    let frame = Frame::encode_data(1, FLAG_SYN | flags, &alloc::vec![7; len]).unwrap();
    server.handle_data(&frame).unwrap();
    assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_ACK);
    server
}

#[test]
fn window_credit_returns_only_for_acknowledged_bytes() {
    let window = DEFAULT_RECEIVE_WINDOW as usize;
    let mut server = server_with_delivered(config(), window, 0);
    while server.poll_event().is_some() {}
    assert_eq!(server.poll_frame(), None, "unread bytes return no credit");
    let more = Frame::encode_data(1, 0, &[0]).unwrap();
    assert_eq!(
        server_with_delivered(config(), window, 0).handle_data(&more),
        Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
    );

    server.ack(1, window / 2 - 1).unwrap();
    assert_eq!(server.poll_frame(), None, "credit returns in half windows");
    server.ack(1, 1).unwrap();
    let update = decode(&outbound(&mut server));
    assert_eq!(update.frame_type(), FrameType::WindowUpdate);
    assert_eq!(update.value() as usize, window / 2);
    server.handle_data(&more).unwrap();
}

#[test]
fn an_over_ack_names_the_stream_and_both_counts_and_acks_nothing() {
    let mut server = server_with_delivered(config(), 10, 0);
    assert_eq!(
        server.ack(1, 11),
        Err(YamuxError::AckExceedsDelivered {
            stream: 1,
            acked: 11,
            unacked: 10,
        })
    );
    server.ack(1, 10).unwrap();
    assert_eq!(
        server.ack(1, 1),
        Err(YamuxError::AckExceedsDelivered {
            stream: 1,
            acked: 1,
            unacked: 0,
        })
    );
    server.ack(9, 1_000).unwrap();
}

#[test]
fn a_closed_stream_keeps_its_slot_until_its_bytes_are_acknowledged() {
    let mut limits = config();
    limits.max_streams = 1;
    let mut server = server_with_delivered(limits, 10, FLAG_FIN);
    server.close_write(1).unwrap();
    while server.poll_frame().is_some() {}
    assert!(
        server
            .poll_events()
            .contains(&YamuxOutput::StreamClosed { stream: 1 })
    );
    let open = |stream| Frame::window_update(stream, FLAG_SYN, 0).unwrap().encode();

    assert_eq!(server.open_stream(), Err(YamuxError::TooManyStreams));
    server.handle_data(&open(3)).unwrap();
    assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);

    server.ack(1, 4).unwrap();
    server.handle_data(&open(5)).unwrap();
    assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);
    assert_eq!(
        server.ack(1, 7),
        Err(YamuxError::AckExceedsDelivered {
            stream: 1,
            acked: 7,
            unacked: 6,
        })
    );

    server.ack(1, 6).unwrap();
    server.handle_data(&open(7)).unwrap();
    assert_eq!(
        server.poll_events(),
        alloc::vec![YamuxOutput::IncomingStream { stream: 7 }]
    );
    server.ack(1, 1).unwrap();
}

#[test]
fn stream_churn_with_an_unread_reader_stays_within_max_streams_times_the_window() {
    let mut limits = config();
    limits.max_streams = 4;
    let window = limits.receive_window as usize;
    let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
    let mut delivered = 0;
    for stream in (1..200).step_by(2) {
        let frame = Frame::encode_data(stream, FLAG_SYN, &alloc::vec![7; window]).unwrap();
        server.handle_data(&frame).unwrap();
        server
            .handle_data(&Frame::data(stream, FLAG_RST, Vec::new()).unwrap().encode())
            .unwrap();
        while server.poll_frame().is_some() {}
        for event in server.poll_events() {
            if let YamuxOutput::Data { data, .. } = event {
                delivered += data.len();
            }
        }
    }
    assert_eq!(delivered, 4 * window, "refused streams deliver nothing");
}

#[test]
fn a_peer_cannot_reopen_an_unsettled_stream_id() {
    let mut server = server_with_delivered(config(), 10, 0);
    server
        .handle_data(&Frame::data(1, FLAG_RST, Vec::new()).unwrap().encode())
        .unwrap();
    let reopen = Frame::encode_data(1, FLAG_SYN, &[7; 10]).unwrap();
    assert_eq!(
        server.handle_data(&reopen),
        Err(YamuxError::Protocol("duplicate SYN for an existing stream"))
    );
    let mut server = server_with_delivered(config(), 10, 0);
    server
        .handle_data(&Frame::data(1, FLAG_RST, Vec::new()).unwrap().encode())
        .unwrap();
    let reopen = Frame::window_update(1, FLAG_SYN, 0).unwrap().encode();
    assert_eq!(
        server.handle_data(&reopen),
        Err(YamuxError::Protocol("duplicate SYN for an existing stream"))
    );
}

#[test]
fn a_local_reset_abandons_unacknowledged_bytes() {
    let mut limits = config();
    limits.max_streams = 1;
    let mut server = server_with_delivered(limits.clone(), 10, 0);
    server.reset(1).unwrap();
    assert_eq!(server.open_stream(), Ok(2), "the reset settled stream 1");

    let mut server = server_with_delivered(limits, 10, 0);
    server
        .handle_data(&Frame::data(1, FLAG_RST, Vec::new()).unwrap().encode())
        .unwrap();
    assert_eq!(server.open_stream(), Err(YamuxError::TooManyStreams));
    server.reset(1).unwrap();
    assert_eq!(server.open_stream(), Ok(2));
}

fn unsettled(session: &YamuxSession) -> Vec<(u32, usize)> {
    session.unsettled_streams().collect()
}

#[test]
fn the_session_ending_keeps_unacknowledged_counts_for_its_host() {
    let go_away = Frame::go_away(0).encode();
    let garbage = [0xff; 12];
    for end in 0..3 {
        let mut server = server_with_delivered(config(), 10, 0);
        while server.poll_event().is_some() {}
        server.ack(1, 4).unwrap();
        match end {
            0 => server.go_away(0),
            1 => server.handle_data(&go_away).unwrap(),
            _ => assert!(server.handle_data(&garbage).is_err()),
        }
        assert_eq!(unsettled(&server), [(1, 6)], "end {end}");
        server.ack(1, 2).unwrap();
        assert_eq!(
            server.ack(1, 5),
            Err(YamuxError::AckExceedsDelivered {
                stream: 1,
                acked: 5,
                unacked: 4,
            })
        );
        server.reset(1).unwrap();
        assert_eq!(unsettled(&server), [], "end {end}");
    }
}

#[test]
fn a_protocol_failure_counts_only_data_it_still_delivers() {
    let mut server = YamuxSession::with_config(YamuxRole::Server, config()).unwrap();
    let mut input = Frame::encode_data(1, FLAG_SYN, &[7; 10]).unwrap();
    input.extend_from_slice(&[0xff; 12]);
    assert!(server.handle_data(&input).is_err());
    assert_eq!(unsettled(&server), []);

    let mut server = YamuxSession::with_config(YamuxRole::Server, config()).unwrap();
    let mut input = Frame::encode_data(1, FLAG_SYN, &[7; 10]).unwrap();
    input.extend(Frame::data(1, FLAG_RST, Vec::new()).unwrap().encode());
    input.extend_from_slice(&[0xff; 12]);
    assert!(server.handle_data(&input).is_err());
    assert_eq!(unsettled(&server), []);
}

#[test]
fn inbound_capacity_resets_only_excess_stream() {
    let mut limits = config();
    limits.max_streams = 1;
    let mut server = YamuxSession::with_config(YamuxRole::Server, limits).unwrap();
    server
        .handle_data(&Frame::window_update(1, FLAG_SYN, 0).unwrap().encode())
        .unwrap();
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::IncomingStream { stream: 1 })
    );
    server
        .handle_data(&Frame::window_update(3, FLAG_SYN, 0).unwrap().encode())
        .unwrap();
    assert_eq!(decode(&outbound(&mut server)).flags(), FLAG_RST);
    assert_eq!(server.stream_count(), 1);
}

#[test]
fn local_capacity_and_id_exhaustion_do_not_damage_existing_streams() {
    let mut limits = config();
    limits.max_streams = 1;
    let mut client = YamuxSession::with_config(YamuxRole::Client, limits).unwrap();
    assert_eq!(client.open_stream().unwrap(), 1);
    assert_eq!(client.open_stream(), Err(YamuxError::TooManyStreams));
    client.config.max_streams = 2;
    client.next_stream_id = Some(u32::MAX);
    assert_eq!(client.open_stream().unwrap(), u32::MAX);
    client.config.max_streams = 3;
    assert_eq!(client.open_stream(), Err(YamuxError::StreamsExhausted));
    assert_eq!(client.stream_count(), 2);
}

#[test]
fn receive_window_violation_emits_protocol_go_away() {
    let mut server = YamuxSession::new(YamuxRole::Server);
    let full = Frame::data(1, FLAG_SYN, alloc::vec![0; DEFAULT_RECEIVE_WINDOW as usize])
        .unwrap()
        .encode();
    server.handle_data(&full).unwrap();
    let over = Frame::data(1, 0, alloc::vec![0; 1]).unwrap().encode();
    assert_eq!(
        server.handle_data(&over),
        Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
    );
    let go_away = decode(&outbound(&mut server));
    assert_eq!(go_away.frame_type(), FrameType::GoAway);
    assert_eq!(go_away.value(), 1);
    assert_eq!(server.handle_data(&[]), Err(YamuxError::Failed));
}

#[test]
fn non_empty_data_after_remote_fin_is_a_protocol_error() {
    let mut server = YamuxSession::new(YamuxRole::Server);
    server
        .handle_data(
            &Frame::data(1, FLAG_SYN | FLAG_FIN, b"final".to_vec())
                .unwrap()
                .encode(),
        )
        .unwrap();
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::IncomingStream { stream: 1 })
    );
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::Data {
            stream: 1,
            data: b"final".to_vec()
        })
    );
    assert_eq!(
        server.poll_output(),
        Some(YamuxOutput::RemoteWriteClosed { stream: 1 })
    );

    server
        .handle_data(&Frame::data(1, 0, Vec::new()).unwrap().encode())
        .unwrap();
    server
        .handle_data(&Frame::window_update(1, 0, 1).unwrap().encode())
        .unwrap();

    assert_eq!(
        server.handle_data(&Frame::data(1, 0, b"late".to_vec()).unwrap().encode()),
        Err(YamuxError::Protocol("data after FIN"))
    );
    let go_away = decode(&outbound(&mut server));
    assert_eq!(go_away.frame_type(), FrameType::GoAway);
    assert_eq!(go_away.value(), 1);
    assert_eq!(server.poll_output(), None, "the failure ends the stream");
}

#[test]
fn coalesced_data_cannot_spend_unadvertised_window_credit() {
    let mut server = YamuxSession::new(YamuxRole::Server);
    let first_len = DEFAULT_RECEIVE_WINDOW / 2 + 1;
    let second_len = DEFAULT_RECEIVE_WINDOW - first_len + 1;
    let mut coalesced = Frame::data(1, FLAG_SYN, alloc::vec![1; first_len as usize])
        .unwrap()
        .encode();
    coalesced.extend(
        Frame::data(1, 0, alloc::vec![2; second_len as usize])
            .unwrap()
            .encode(),
    );

    assert_eq!(
        server.handle_data(&coalesced),
        Err(YamuxError::ReceiveWindowExceeded { stream: 1 })
    );
    let go_away = decode(&outbound(&mut server));
    assert_eq!(go_away.frame_type(), FrameType::GoAway);
    assert_eq!(go_away.value(), 1);
}

#[test]
fn ping_is_echoed_and_go_away_closes_streams() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    let stream = session.open_stream().unwrap();
    session
        .handle_data(&Frame::ping(FLAG_SYN, 42).unwrap().encode())
        .unwrap();
    let pong = decode(&outbound(&mut session));
    assert_eq!(pong.flags(), FLAG_ACK);
    assert_eq!(pong.value(), 42);

    session.handle_data(&Frame::go_away(0).encode()).unwrap();
    assert_eq!(
        session.poll_output(),
        Some(YamuxOutput::GoAwayReceived { code: 0 })
    );
    assert_eq!(
        session.poll_output(),
        Some(YamuxOutput::StreamClosed { stream })
    );
    assert_eq!(session.open_stream(), Err(YamuxError::SessionClosed));
}

#[test]
fn quiet_session_sends_ping_after_keepalive_interval() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();
    assert_eq!(session.poll_output(), None, "nothing is due at t=0");

    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS - 1))
        .unwrap();
    assert_eq!(
        session.poll_output(),
        None,
        "a ping one millisecond early would be early"
    );

    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .unwrap();
    let ping = decode(&outbound(&mut session));
    assert_eq!(ping.frame_type(), FrameType::Ping);
    assert_eq!(ping.flags(), FLAG_SYN);
    assert_ne!(ping.value(), 0, "the nonce is an opaque non-zero value");
    assert_eq!(session.poll_output(), None);
}

#[test]
fn inbound_traffic_defers_the_keepalive_ping() {
    let mut session = YamuxSession::new(YamuxRole::Server);
    session.poll(Now::from_millis(0)).unwrap();

    session
        .handle_data(&Frame::ping(FLAG_SYN, 7).unwrap().encode())
        .unwrap();
    let pong = decode(&outbound(&mut session));
    assert_eq!(pong.flags(), FLAG_ACK);
    assert_eq!(pong.value(), 7);

    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .unwrap();
    assert_eq!(
        session.poll_output(),
        None,
        "the echoed ping was traffic; the next keepalive is another interval out"
    );

    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS * 2))
        .unwrap();
    let ping = decode(&outbound(&mut session));
    assert_eq!(ping.frame_type(), FrameType::Ping);
    assert_eq!(ping.flags(), FLAG_SYN);
}

#[test]
fn outbound_traffic_does_not_postpone_the_probe() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();
    let stream = session.open_stream().unwrap();
    session
        .send(stream, Bytes::from(b"hello".to_vec()))
        .unwrap();
    assert_eq!(decode(&outbound(&mut session)).payload(), b"hello");

    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .unwrap();
    let ping = decode(&outbound(&mut session));
    assert_eq!(
        (ping.frame_type(), ping.flags()),
        (FrameType::Ping, FLAG_SYN),
        "writing alone does not show the peer is alive"
    );
}

#[test]
fn peer_acknowledged_sends_postpone_the_probe() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();

    session.note_peer_acked();
    session.poll(Now::from_millis(5)).unwrap();
    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .unwrap();
    assert_eq!(session.poll_frame(), None, "the peer is alive: no probe");
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::from_millis(5 + KEEPALIVE_INTERVAL_MS))
    );

    session
        .poll(Now::from_millis(5 + KEEPALIVE_INTERVAL_MS))
        .unwrap();
    let ping = decode(&outbound(&mut session));
    assert_eq!(
        (ping.frame_type(), ping.flags()),
        (FrameType::Ping, FLAG_SYN),
        "an interval without progress probes again"
    );
}

/// A session whose keepalive ping came due at the interval and is still
/// queued.
fn probing_session() -> YamuxSession {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();
    session
        .poll(Now::from_millis(KEEPALIVE_INTERVAL_MS))
        .unwrap();
    session
}

#[test]
fn a_ping_not_handed_off_in_time_fails_the_session() {
    let mut session = probing_session();
    let stream = session.open_stream().unwrap();
    let due = KEEPALIVE_INTERVAL_MS;
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::from_millis(due + KEEPALIVE_HANDOFF_TIMEOUT_MS))
    );
    session
        .handle_data(&Frame::ping(FLAG_SYN, 9).unwrap().encode())
        .unwrap();
    session
        .poll(Now::from_millis(due + KEEPALIVE_HANDOFF_TIMEOUT_MS - 1))
        .unwrap();

    assert_eq!(
        session.poll(Now::from_millis(due + KEEPALIVE_HANDOFF_TIMEOUT_MS)),
        Err(YamuxError::KeepaliveTimeout)
    );
    assert!(
        session.poll_events().is_empty(),
        "stream {stream} ends with the session, not with a close of its own"
    );
    assert_eq!(session.poll_frame(), None, "no GoAway for a dead peer");
    assert_eq!(session.next_deadline(), None);
    assert_eq!(
        session.poll(Now::from_millis(due + KEEPALIVE_HANDOFF_TIMEOUT_MS)),
        Err(YamuxError::Failed)
    );
}

#[test]
fn a_due_ping_queues_behind_unpulled_control_frames_and_keeps_its_clock() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();
    session
        .handle_data(&Frame::ping(FLAG_SYN, 9).unwrap().encode())
        .unwrap();
    let due = KEEPALIVE_INTERVAL_MS + 5;
    session.poll(Now::from_millis(5)).unwrap();
    session.poll(Now::from_millis(due)).unwrap();

    let ack = decode(&outbound(&mut session));
    assert_eq!((ack.flags(), ack.value()), (FLAG_ACK, 9));
    let ping = decode(&outbound(&mut session));
    assert_eq!(ping.flags(), FLAG_SYN, "the ping queues; it is not skipped");
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::IMMEDIATE),
        "a poll must date the hand-off"
    );
    session.poll(Now::from_millis(due + 1)).unwrap();
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::from_millis(due + 1 + KEEPALIVE_ACK_TIMEOUT_MS))
    );
}

#[test]
fn only_an_ack_with_the_pings_nonce_answers_it() {
    let mut session = probing_session();
    let ping = decode(&outbound(&mut session));
    let sent = KEEPALIVE_INTERVAL_MS + 1;
    session.poll(Now::from_millis(sent)).unwrap();

    let stray = Frame::ping(FLAG_ACK, ping.value().wrapping_add(1)).unwrap();
    session.handle_data(&stray.encode()).unwrap();
    session
        .poll(Now::from_millis(sent + KEEPALIVE_ACK_TIMEOUT_MS - 1))
        .unwrap();
    assert_eq!(
        session.poll(Now::from_millis(sent + KEEPALIVE_ACK_TIMEOUT_MS)),
        Err(YamuxError::KeepaliveTimeout)
    );
}

#[test]
fn peer_acknowledged_sends_do_not_answer_a_ping() {
    let mut session = probing_session();
    let _ping = decode(&outbound(&mut session));
    let sent = KEEPALIVE_INTERVAL_MS + 1;
    session.poll(Now::from_millis(sent)).unwrap();

    session.note_peer_acked();
    session
        .poll(Now::from_millis(sent + KEEPALIVE_ACK_TIMEOUT_MS - 1))
        .unwrap();
    assert_eq!(
        session.poll(Now::from_millis(sent + KEEPALIVE_ACK_TIMEOUT_MS)),
        Err(YamuxError::KeepaliveTimeout)
    );
}

#[test]
fn a_matching_ack_restarts_the_quiet_interval() {
    let mut session = probing_session();
    let ping = decode(&outbound(&mut session));
    let sent = KEEPALIVE_INTERVAL_MS + 1;
    session.poll(Now::from_millis(sent)).unwrap();

    session
        .handle_data(&Frame::ping(FLAG_ACK, ping.value()).unwrap().encode())
        .unwrap();
    let answered = sent + KEEPALIVE_ACK_TIMEOUT_MS - 1;
    session.poll(Now::from_millis(answered)).unwrap();
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::from_millis(answered + KEEPALIVE_INTERVAL_MS))
    );
    session
        .poll(Now::from_millis(answered + KEEPALIVE_INTERVAL_MS))
        .unwrap();
    let next = decode(&outbound(&mut session));
    assert_ne!(next.value(), ping.value(), "each probe has its own nonce");
}

#[test]
fn next_deadline_is_the_keepalive_interval_after_the_first_poll() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    assert_eq!(
        session.next_deadline(),
        None,
        "no sample yet means no timeline to answer on"
    );

    session.poll(Now::from_millis(10)).unwrap();
    assert_eq!(
        session.next_deadline(),
        Some(Deadline::from_millis(10 + KEEPALIVE_INTERVAL_MS))
    );
}

#[test]
fn a_closed_session_does_not_keepalive() {
    let mut session = YamuxSession::new(YamuxRole::Client);
    session.poll(Now::from_millis(0)).unwrap();
    session.go_away(0);
    let _ = outbound(&mut session);

    assert_eq!(
        session.poll(Now::from_millis(KEEPALIVE_INTERVAL_MS)),
        Err(YamuxError::SessionClosed)
    );
    assert_eq!(session.poll_output(), None);
    assert_eq!(session.next_deadline(), None);
}

#[test]
fn rst_before_ack_surfaces_stream_closed() {
    let mut client = YamuxSession::new(YamuxRole::Client);
    let stream = client.open_stream().unwrap();
    client
        .handle_data(&Frame::data(stream, FLAG_RST, Vec::new()).unwrap().encode())
        .unwrap();
    assert_eq!(
        client.poll_output(),
        Some(YamuxOutput::StreamClosed { stream })
    );
}

/// A receive window past the initial credit and `max_frame_len`.
fn large_window_config() -> YamuxConfig {
    YamuxConfig {
        receive_window: 2 * 1024 * 1024,
        ..YamuxConfig::default()
    }
}

#[test]
fn a_frame_as_large_as_the_granted_credit_is_accepted() {
    let config = large_window_config();
    let window = config.receive_window as usize;
    assert!(window > config.max_frame_len as usize);
    let mut client = YamuxSession::with_config(YamuxRole::Client, config).unwrap();
    let open = Frame::window_update(2, FLAG_SYN, 0).unwrap().encode();
    client.handle_data(&open).unwrap();
    while client.poll_frame().is_some() {}

    let frame = Frame::data(2, 0, alloc::vec![7; window]).unwrap().encode();
    client.handle_data(&frame).unwrap();
    let delivered: usize = client
        .poll_events()
        .iter()
        .map(|event| match event {
            YamuxOutput::Data { data, .. } => data.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(delivered, window);
}

#[test]
fn a_window_past_the_initial_credit_is_granted_with_the_open() {
    let window = large_window_config().receive_window;
    let mut client = YamuxSession::with_config(YamuxRole::Client, large_window_config()).unwrap();
    let mut server = YamuxSession::with_config(YamuxRole::Server, large_window_config()).unwrap();
    let stream = client.open_stream().unwrap();
    client.send(stream, Bytes::from_static(b"hi")).unwrap();
    let open = decode(&outbound(&mut client));
    assert_eq!(open.frame_type(), FrameType::WindowUpdate);
    assert_eq!(open.flags(), FLAG_SYN);
    assert_eq!(open.value(), window - DEFAULT_RECEIVE_WINDOW);

    server.handle_data(&open.encode()).unwrap();
    server.poll_events();
    let window = window as usize;
    let payload = Bytes::from(alloc::vec![7; window]);
    let mut sent = 0;
    while sent < window {
        let unsent = match server.send(stream, payload.slice(sent..)) {
            Ok(()) => Bytes::new(),
            Err(YamuxError::Full { unsent, .. }) => unsent,
            Err(error) => panic!("{error}"),
        };
        sent = window - unsent.len();
        while let Some(frame) = server.poll_frame() {
            client.handle_data(&frame).unwrap();
        }
    }
    let delivered: usize = client
        .poll_events()
        .iter()
        .map(|event| match event {
            YamuxOutput::Data { data, .. } => data.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(delivered, window);
}
