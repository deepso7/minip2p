//! Runnable caller sketches. Every scenario uses the same 8-byte model buffers.
use minip2p_stream_dx_prototype::helper::{PendingWrite, ReadContinuation, ReadStep};
use minip2p_stream_dx_prototype::{Endpoint, Error, Event, drive};

const MESSAGE: &[u8] = b"hello from a tiny buffer";

fn state(a: &Endpoint, b: &Endpoint, accepted: usize, received: usize) {
    println!(
        "  app: accepted={accepted}/{} received={received}",
        MESSAGE.len()
    );
    println!("  sender: {:?}\n  reader: {:?}", a.snapshot(), b.snapshot());
}

// BEGIN PARTIAL CALLER
fn partial_transfer() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let send = sender.stream();
    let mut offset = 0;
    let mut writable = true;
    let mut readable = true; // This continuation is the application's responsibility.
    let mut eof = false;
    let mut received = Vec::new();
    let mut scratch = [0; 5];

    for turn in 0..32 {
        println!("turn {turn}");
        while let Some(event) = sender.pop_event() {
            if matches!(event, Event::Writable(_)) {
                writable = true;
            }
        }
        if writable && offset < MESSAGE.len() {
            match sender.try_write(send, &MESSAGE[offset..]) {
                Ok(n) => {
                    offset += n;
                    println!("  write accepted {n}");
                }
                Err(Error::WouldBlock) => {
                    writable = false;
                    println!("  write would block");
                }
                Err(error) => panic!("unexpected write failure: {error:?}"),
            }
        }
        if offset == MESSAGE.len() {
            sender.finish(send).unwrap();
        }
        println!("  drive moved {}", drive(&mut sender, &mut reader, 4));
        if turn >= 5 {
            while let Some(event) = reader.pop_event() {
                if matches!(event, Event::Readable(_) | Event::RemoteWriteClosed(_)) {
                    readable = true;
                }
            }
            // One read per turn, exactly as in helper_transfer. Positive reads
            // must retain readable=true even when no further event is queued.
            if readable {
                match reader.try_read(reader.stream(), &mut scratch) {
                    Ok(0) => {
                        eof = true;
                        readable = false;
                        println!("  EOF");
                    }
                    Ok(n) => {
                        received.extend_from_slice(&scratch[..n]);
                        println!("  read {n}; yield");
                    }
                    Err(Error::WouldBlock) => readable = false,
                    Err(error) => panic!("unexpected read failure: {error:?}"),
                }
            }
        }
        state(&sender, &reader, offset, received.len());
        println!("  caller: writable={writable} readable={readable} eof={eof}");
        if eof {
            break;
        }
    }
    println!(
        "received {:?}; complete={}\n",
        String::from_utf8_lossy(&received),
        received == MESSAGE
    );
}
// END PARTIAL CALLER

// BEGIN OWNED CALLER
fn owned_transfer() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let send = sender.stream();
    let mut offset = 0;
    let mut received = Vec::new();
    for turn in 0..32 {
        println!("turn {turn}");
        if offset < MESSAGE.len() {
            // Whole chunks must fit. A failed attempt consumed its Vec.
            let end = (offset + 6).min(MESSAGE.len());
            match sender.legacy_send_owned(send, MESSAGE[offset..end].to_vec()) {
                Ok(()) => {
                    println!("  whole chunk accepted {}", end - offset);
                    offset = end;
                }
                Err(Error::WouldBlock) => println!("  whole chunk rejected; retry on next turn"),
                Err(error) => panic!("unexpected write failure: {error:?}"),
            }
        }
        if offset == MESSAGE.len() {
            sender.finish(send).unwrap();
        }
        println!("  drive moved {}", drive(&mut sender, &mut reader, 4));
        if turn >= 5 {
            let data = reader.legacy_take_data();
            println!("  owned receive chunk: {} bytes", data.len());
            received.extend(data);
            while reader.pop_event().is_some() {} // Readiness is irrelevant to this sketch.
        }
        state(&sender, &reader, offset, received.len());
        if reader.snapshot().remote_fin && received.len() == MESSAGE.len() {
            break;
        }
    }
    println!(
        "received {:?}; complete={}\n",
        String::from_utf8_lossy(&received),
        received == MESSAGE
    );
}
// END OWNED CALLER

// BEGIN HELPER CALLER
fn helper_transfer() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let send = sender.stream();
    let mut write = PendingWrite::new(send, MESSAGE);
    let mut read = ReadContinuation::new(reader.stream());
    let mut scratch = [0; 5];
    let mut received = Vec::new();

    for turn in 0..32 {
        println!("turn {turn}");
        while let Some(event) = sender.pop_event() {
            write.on_event(&event);
        }
        if write.is_runnable() {
            println!("  write step: {:?}", write.step(&mut sender).unwrap());
        }
        if write.is_complete() {
            sender.finish(send).unwrap();
        }
        println!("  drive moved {}", drive(&mut sender, &mut reader, 4));

        if turn >= 5 {
            while let Some(event) = reader.pop_event() {
                read.on_event(&event);
            }
            // One read per host turn. The handler deliberately yields after it.
            if read.is_runnable() {
                match read.step(&mut reader, &mut scratch).unwrap() {
                    ReadStep::Data(n) => received.extend_from_slice(&scratch[..n]),
                    ReadStep::Eof => println!("  EOF"),
                    ReadStep::Waiting | ReadStep::EmptyBuffer => {}
                }
            }
        }
        state(
            &sender,
            &reader,
            MESSAGE.len() - write.remaining().len(),
            received.len(),
        );
        println!(
            "  helper: write_runnable={} read_runnable={} pending={} eof={}",
            write.is_runnable(),
            read.is_runnable(),
            write.remaining().len(),
            read.is_eof()
        );
        // A real host includes these helpers in its runnable set before sleeping.
        // If the application is paused, it resumes the helper when it resumes itself.
        if read.is_eof() {
            break;
        }
    }
    println!(
        "received {:?}; complete={}\n",
        String::from_utf8_lossy(&received),
        received == MESSAGE
    );
}
// END HELPER CALLER

fn helper_yield_and_error() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let mut read = ReadContinuation::new(reader.stream());
    sender.try_write(sender.stream(), b"abcdefgh").unwrap();
    drive(&mut sender, &mut reader, 8);
    while let Some(event) = reader.pop_event() {
        read.on_event(&event);
    }
    for turn in 0..5 {
        println!(
            "read turn {turn}: {:?}",
            read.step(&mut reader, &mut [0; 2])
        );
        println!(
            "  unread={} event={:?} helper_runnable={}",
            reader.snapshot().queued_receive,
            reader.pop_event(),
            read.is_runnable()
        );
    }
    println!(
        "idle step: {:?}; runnable={}",
        read.step(&mut reader, &mut [0; 2]),
        read.is_runnable()
    );
    sender.finish(sender.stream()).unwrap();
    drive(&mut sender, &mut reader, 4);
    while let Some(event) = reader.pop_event() {
        read.on_event(&event);
    }
    println!("empty destination: {:?}", read.step(&mut reader, &mut []));
    println!(
        "EOF wake: {:?}; runnable={}",
        read.step(&mut reader, &mut [0; 2]),
        read.is_runnable()
    );

    let mut failing_sender = Endpoint::new(8);
    let mut write = PendingWrite::new(failing_sender.stream(), MESSAGE);
    println!(
        "write before failure: {:?}",
        write.step(&mut failing_sender)
    );
    failing_sender.replace_connection();
    println!(
        "stale write: {:?}; unaccepted={} runnable={}",
        write.step(&mut failing_sender),
        write.remaining().len(),
        write.is_runnable()
    );
    let mut stale_read = ReadContinuation::new(reader.stream());
    reader.replace_connection();
    println!(
        "stale read: {:?}; runnable={}\n",
        stale_read.step(&mut reader, &mut [0; 2]),
        stale_read.is_runnable()
    );
}

fn early_yield() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let stream = reader.stream();
    sender.try_write(sender.stream(), b"abcdefgh").unwrap();
    drive(&mut sender, &mut reader, 8);
    println!("notification: {:?}", reader.pop_event());
    println!(
        "read only {} bytes",
        reader.try_read(stream, &mut [0; 2]).unwrap()
    );
    for _ in 0..3 {
        drive(&mut sender, &mut reader, 8);
    }
    println!(
        "after three more drives: event={:?}, unread={}",
        reader.pop_event(),
        reader.snapshot().queued_receive
    );
    println!("A caller waiting for another notification is now stuck.");
    println!(
        "Continue reading explicitly: {:?}",
        reader.try_read(stream, &mut [0; 8])
    );
    println!(
        "Read again to re-arm: {:?}",
        reader.try_read(stream, &mut [0; 8])
    );
    sender.try_write(sender.stream(), b"ij").unwrap();
    drive(&mut sender, &mut reader, 8);
    println!("new data after re-arm: {:?}\n", reader.pop_event());
}

fn fin_and_stale() {
    let (mut sender, mut reader) = (Endpoint::new(8), Endpoint::new(8));
    let old = sender.stream();
    sender.try_write(old, b"tail").unwrap();
    sender.finish(old).unwrap();
    println!("write after FIN: {:?}", sender.try_write(old, b"too late"));
    drive(&mut sender, &mut reader, 8);
    while let Some(event) = reader.pop_event() {
        println!("event: {event:?}");
    }
    let read = reader.stream();
    println!(
        "read buffered prefix after FIN: {:?}",
        reader.try_read(read, &mut [0; 8])
    );
    println!("then EOF: {:?}", reader.try_read(read, &mut [0; 8]));
    sender.replace_connection();
    println!(
        "write using replaced connection's handle: {:?}\n",
        sender.try_write(old, b"stale")
    );
}

fn main() {
    println!("THROWAWAY stream DX model; no network or performance measurement.\n");
    match std::env::args().nth(1).as_deref() {
        Some("partial") => partial_transfer(),
        Some("owned") => owned_transfer(),
        Some("helper") => helper_transfer(),
        Some("helper-yield") => helper_yield_and_error(),
        Some("yield") => early_yield(),
        Some("fin") => fin_and_stale(),
        None | Some("all") => {
            println!("=== Owned chunks ===");
            owned_transfer();
            println!("=== Partial writes and pull reads ===");
            partial_transfer();
            println!("=== Helper with one read per turn ===");
            helper_transfer();
            println!("=== Early yield ===");
            early_yield();
            println!("=== Helper resumes after yield; EOF and errors ===");
            helper_yield_and_error();
            println!("=== FIN and stale handles ===");
            fin_and_stale();
        }
        _ => eprintln!("usage: cargo run -- [all|owned|partial|helper|yield|helper-yield|fin]"),
    }
}
