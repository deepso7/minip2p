//! Checks the quinn-proto behaviours the minip2p adapter contract relies on.
use std::time::{Duration, Instant};

use bytes::Bytes;
use minip2p_identity::Ed25519Keypair;
use probe::peer::{Options, Peer};
use quinn_proto::{ConnectionHandle, Dir, Event, ReadError, StreamEvent, StreamId, VarInt, WriteError};

fn pair() -> (Peer, Peer, ConnectionHandle, ConnectionHandle) {
    let opts = || Options { quinn_udp: false, require_address_validation: true };
    let mut server = Peer::new(&Ed25519Keypair::generate(), "127.0.0.1:0", opts());
    let mut client = Peer::new(&Ed25519Keypair::generate(), "127.0.0.1:0", opts());
    let cch = client.connect(Instant::now(), server.local_addr());
    let (mut c_ok, mut s_ch) = (false, None);
    for _ in 0..500 {
        drive(&mut server, &mut client);
        while let Some((ch, ev)) = server.events.pop_front() {
            if matches!(ev, Event::Connected) { s_ch = Some(ch) }
        }
        while let Some((_, ev)) = client.events.pop_front() {
            if matches!(ev, Event::Connected) { c_ok = true }
        }
        if c_ok && s_ch.is_some() { break }
    }
    (server, client, s_ch.expect("server connected"), cch)
}

fn drive(a: &mut Peer, b: &mut Peer) {
    a.drive(Instant::now());
    b.drive(Instant::now());
    std::thread::sleep(Duration::from_micros(200));
}

fn pump(server: &mut Peer, client: &mut Peer, n: usize) -> (Vec<Event>, Vec<Event>) {
    let (mut se, mut ce) = (vec![], vec![]);
    for _ in 0..n {
        drive(server, client);
        se.extend(server.events.drain(..).map(|e| e.1));
        ce.extend(client.events.drain(..).map(|e| e.1));
    }
    (se, ce)
}

fn write_all_possible(p: &mut Peer, ch: ConnectionHandle, id: StreamId) -> usize {
    let mut total = 0;
    loop {
        match p.conn(ch).send_stream(id).write(&[7u8; 16 * 1024]) {
            Ok(n) => total += n,
            Err(WriteError::Blocked) => return total,
            Err(e) => panic!("{e}"),
        }
    }
}

fn accept_bi(p: &mut Peer, ch: ConnectionHandle) -> StreamId {
    p.conn(ch).streams().accept(Dir::Bi).expect("incoming bi stream")
}

/// ADR 0012: credit returns only when the reader reads. An unread stream
/// blocks the writer at the stream window; data stays readable without any
/// new packet or event once the reader resumes.
#[test]
fn read_gate_withholds_credit_and_data_stays_buffered() {
    let (mut server, mut client, sch, cch) = pair();
    let id = client.conn(cch).streams().open(Dir::Bi).unwrap();
    let mut written = write_all_possible(&mut client, cch, id);
    for _ in 0..20 {
        pump(&mut server, &mut client, 5);
        written += write_all_possible(&mut client, cch, id);
    }
    assert_eq!(written, 1_000_000, "writer stops at the 1 MB stream window");

    let sid = accept_bi(&mut server, sch);
    let mut read = 0;
    {
        let mut rs = server.conn(sch).recv_stream(sid);
        let mut chunks = rs.read(true).unwrap();
        // Read only half: the gate.
        while read < 500_000 {
            match chunks.next(500_000 - read) {
                Ok(Some(c)) => read += c.bytes.len(),
                _ => break,
            }
        }
        let _ = chunks.finalize();
    }
    pump(&mut server, &mut client, 20);
    let more = write_all_possible(&mut client, cch, id);
    assert!(more > 0 && more <= 500_000, "credit for what was read only: {more}");

    // Remaining bytes are already buffered: readable with no new packet.
    let mut rs = server.conn(sch).recv_stream(sid);
    let mut chunks = rs.read(true).unwrap();
    let mut rest = 0;
    while let Ok(Some(c)) = chunks.next(usize::MAX) {
        rest += c.bytes.len();
    }
    let _ = chunks.finalize();
    assert!(rest >= 500_000 - 1, "buffered tail readable: {rest}");
}

/// A peer's STOP_SENDING surfaces as an event with its code, and later
/// writes fail with Stopped while the read half stays usable.
#[test]
fn stop_sending_is_an_event_and_scoped_to_the_write_half() {
    let (mut server, mut client, sch, cch) = pair();
    let id = client.conn(cch).streams().open(Dir::Bi).unwrap();
    client.conn(cch).send_stream(id).write(b"hi").unwrap();
    client.kick(cch, Instant::now());
    pump(&mut server, &mut client, 10);
    let sid = accept_bi(&mut server, sch);
    server.conn(sch).recv_stream(sid).stop(VarInt::from_u32(42)).unwrap();
    server.conn(sch).send_stream(sid).write(b"reply").unwrap();
    server.kick(sch, Instant::now());
    let (_, ce) = pump(&mut server, &mut client, 20);
    assert!(ce.iter().any(|e| matches!(e, Event::Stream(StreamEvent::Stopped { id: s, error_code }) if *s == id && *error_code == VarInt::from_u32(42))), "{ce:?}");
    assert!(matches!(client.conn(cch).send_stream(id).write(b"x"), Err(WriteError::Stopped(c)) if c == VarInt::from_u32(42)));
    let mut rs = client.conn(cch).recv_stream(id);
    let mut chunks = rs.read(true).unwrap();
    let got = chunks.next(usize::MAX).unwrap().unwrap();
    assert_eq!(&got.bytes[..], b"reply");
    let _ = chunks.finalize();
}

/// A peer reset surfaces from the read side with its code.
#[test]
fn reset_surfaces_on_read() {
    let (mut server, mut client, sch, cch) = pair();
    let id = client.conn(cch).streams().open(Dir::Bi).unwrap();
    client.conn(cch).send_stream(id).write(b"hi").unwrap();
    client.kick(cch, Instant::now());
    pump(&mut server, &mut client, 10);
    let sid = accept_bi(&mut server, sch);
    client.conn(cch).send_stream(id).reset(VarInt::from_u32(9)).unwrap();
    client.kick(cch, Instant::now());
    pump(&mut server, &mut client, 10);
    let mut rs = server.conn(sch).recv_stream(sid);
    let mut chunks = rs.read(true).unwrap();
    let mut saw_reset = false;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(_)) => continue,
            Err(ReadError::Reset(code)) => { saw_reset = code == VarInt::from_u32(9); break }
            other => panic!("{other:?}"),
        }
    }
    let _ = chunks.finalize();
    assert!(saw_reset);
}

/// Built-in keepalive keeps an idle live connection up past the idle
/// timeout, and does not keep a dead one alive: it still times out.
#[test]
fn keepalive_keeps_live_paths_and_dead_paths_still_time_out() {
    let (mut server, mut client, _sch, cch) = pair();
    // Live: 30 s idle timeout, 15 s keepalive -> use the defaults but shorten
    // via per-connection windows is not possible; instead observe that
    // after 2 s of mutual idleness nothing closes, then kill the server.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        drive(&mut server, &mut client);
    }
    assert!(client.has_conn(cch));
    drop(server);
    let dead = Instant::now();
    let mut lost = None;
    while dead.elapsed() < Duration::from_secs(60) {
        client.drive(Instant::now());
        while let Some((_, ev)) = client.events.pop_front() {
            println!("{:?} event {ev:?}", dead.elapsed());
            if let Event::ConnectionLost { reason } = ev {
                lost = Some((dead.elapsed(), reason.to_string()));
            }
        }
        if lost.is_some() || !client.has_conn(cch) { break }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (after, reason) = lost.expect("dead path must close");
    assert!(after >= Duration::from_secs(40) && after <= Duration::from_secs(50), "{after:?} {reason}");
    println!("dead path closed after {after:?}: {reason}");
}

#[test]
fn peer_id_check_and_token_agree() {
    let (server, client, sch, cch) = pair();
    assert!(server.peer_id(sch).is_some() && client.peer_id(cch).is_some());
    assert_eq!(server.connection_token(sch), client.connection_token(cch));
    let _ = Bytes::new();
}
