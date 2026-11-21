use super::*;

#[test]
fn abandoning_a_closed_stream_acks_data_left_in_the_endpoint_queue() {
    const PROTOCOL: &str = "/test/abandon-split/1";
    let bind = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .protocol(PROTOCOL)
            .bind()
            .expect("bind endpoint")
    };
    let (mut writer, mut reader) = (bind(), bind());
    let (writer_peer, reader_peer) = (*writer.peer_id(), *reader.peer_id());
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    let tick = Duration::from_millis(5);
    writer
        .connect(reader.listen().expect("listen"))
        .expect("connect");
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(std::time::Instant::now() < give_up, "never ready");
        writer.next_event(tick).expect("drive writer");
        reader.next_event(tick).expect("drive reader");
    }
    let out_stream = writer.open_stream(&reader_peer, PROTOCOL).expect("open");
    let stream = loop {
        assert!(std::time::Instant::now() < give_up, "never negotiated");
        writer.next_event(tick).expect("drive writer");
        if let Some(EndpointEvent::StreamReady { stream, .. }) =
            reader.next_event(tick).expect("drive reader")
        {
            break stream;
        }
    };
    reader.close_stream_write(stream).expect("reader close");
    loop {
        assert!(std::time::Instant::now() < give_up, "reader FIN lost");
        reader.next_event(tick).expect("drive reader");
        if let Some(EndpointEvent::StreamRemoteWriteClosed { stream: closed, .. }) =
            writer.next_event(tick).expect("drive writer")
            && closed.stream_id() == out_stream.stream_id()
        {
            break;
        }
    }
    assert_eq!(
        writer.core().connection_id(&reader_peer),
        Some(out_stream.conn_id())
    );
    writer.send_stream(out_stream, vec![1, 2, 3]).expect("send");
    writer.close_stream_write(out_stream).expect("writer close");
    writer.next_event(tick).expect("flush writer");

    loop {
        assert!(std::time::Instant::now() < give_up, "stream never closed");
        writer.next_event(tick).expect("drive writer");
        match reader.raw_poll_next(tick).expect("poll reader") {
            Some(event @ SwarmEvent::StreamData { stream_id, .. })
                if stream_id == stream.stream_id() =>
            {
                reader.engine.events.push_back(EndpointEvent::from_swarm(
                    event,
                    &mut reader.engine.protocols,
                ));
            }
            Some(event @ SwarmEvent::StreamClosed { stream_id, .. })
                if stream_id == stream.stream_id() =>
            {
                reader.engine.events.push_back(EndpointEvent::from_swarm(
                    event,
                    &mut reader.engine.protocols,
                ));
                break;
            }
            _ => {}
        }
    }

    reader.abandon_stream(stream).expect("abandon");
    reader.stream_consumed(stream, 4).expect("stream settled");
}

#[test]
fn a_half_close_forgets_a_bare_writer_waiting_on_writable() {
    const PROTOCOL: &str = "/test/half-close-wake/1";
    let bind = || {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .protocol(PROTOCOL)
            .bind()
            .expect("bind endpoint")
    };
    let (mut writer, mut reader) = (bind(), bind());
    let (writer_peer, reader_peer) = (*writer.peer_id(), *reader.peer_id());
    let give_up = std::time::Instant::now() + Duration::from_secs(10);
    let tick = Duration::from_millis(5);
    writer
        .connect(reader.listen().expect("listen"))
        .expect("connect");
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(std::time::Instant::now() < give_up, "never ready");
        writer.next_event(tick).expect("drive writer");
        reader.next_event(tick).expect("drive reader");
    }
    let stream = writer.open_stream(&reader_peer, PROTOCOL).expect("open");
    loop {
        assert!(std::time::Instant::now() < give_up, "never negotiated");
        reader.next_event(tick).expect("drive reader");
        if let Some(EndpointEvent::StreamReady { stream: ready, .. }) =
            writer.next_event(tick).expect("drive writer")
            && ready == stream
        {
            break;
        }
    }
    let outcome = writer
        .try_send_stream(stream, vec![0; 16 * 1024 * 1024])
        .expect("try send");
    assert!(!outcome.is_accepted(), "past the stream's send window");
    writer.close_stream_write(stream).expect("close write");
    assert!(!writer.is_write_pending(stream));
    assert!(writer.engine.writes.wake.is_empty());
}
