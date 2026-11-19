//! The bindings' stream writes, queued by the endpoint's own write queue
//! (ADR 0030).
//!
//! A binding hands over one whole payload per write. The endpoint sends as
//! much as the stream accepts, holds the rest, resends it on the stream's
//! Writable, and reports `StreamWriteAccepted` (converted to
//! [`P2pEvent::StreamWriteAccepted`](crate::P2pEvent::StreamWriteAccepted))
//! once every byte has been accepted. The bindings keep at most one pending
//! write per stream, serializing their writes behind that event.

use minip2p::{Bytes, Endpoint, Platform, SendError, StreamKey};

use crate::FfiError;

/// The write budget the bindings' endpoints run with: unbounded, because
/// the bindings already bound what reaches it. The SDK admits writes per
/// stream up to a high-water mark, each stream holds at most one pending
/// write, and the stream limit caps the streams. A refusal here would have
/// no wakeup the SDK waits for.
pub const BINDING_WRITE_BUDGET: usize = usize::MAX;

/// Sends one binding payload: `true` once every byte is accepted, `false`
/// while the endpoint holds the tail. A second write while one is pending is
/// [`FfiError::Backpressure`], or [`FfiError::InvalidState`] once a close is
/// deferred behind it.
pub fn send_whole<P: Platform>(
    endpoint: &mut Endpoint<P>,
    stream: StreamKey,
    data: impl Into<Bytes>,
) -> Result<bool, FfiError> {
    if endpoint.is_write_closing(stream) {
        return Err(map_send_error(SendError::Closing {
            stream,
            unsent: data.into(),
        }));
    }
    if endpoint.is_write_pending(stream) {
        return Err(FfiError::Backpressure);
    }
    endpoint.send_stream(stream, data).map_err(map_send_error)?;
    Ok(!endpoint.is_write_pending(stream))
}

/// Maps a write refusal to the binding's error: a write behind a deferred
/// close is [`FfiError::InvalidState`].
pub fn map_send_error(error: SendError) -> FfiError {
    match error {
        // The unbounded budget never refuses for size; mapped all the same.
        SendError::OverBudget { .. } | SendError::TooLarge { .. } => FfiError::Backpressure,
        SendError::Closing { stream, .. } => FfiError::InvalidState {
            detail: format!("stream {} write side is closing", stream.stream_id()),
        },
        SendError::Driver(error) => crate::map_driver_error(error),
        // A refusal this core predates.
        error => FfiError::InvalidState {
            detail: error.to_string(),
        },
    }
}

#[cfg(all(test, feature = "driver"))]
mod tests {
    use std::time::{Duration, Instant};

    use minip2p::{Endpoint, EndpointEvent, EndpointWaitOutcome};

    use super::*;

    const PROTOCOL: &str = "/minip2p/ffi-writes/1";

    fn bind() -> Endpoint {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("listen address")
            .protocol(PROTOCOL)
            .write_budget(BINDING_WRITE_BUDGET)
            .bind()
            .expect("bind endpoint")
    }

    fn step(endpoint: &mut Endpoint) -> Option<EndpointEvent> {
        match endpoint.wait(Duration::from_millis(2)).expect("drive") {
            EndpointWaitOutcome::Event(event) => Some(event),
            _ => None,
        }
    }

    #[test]
    fn a_write_after_a_deferred_close_is_invalid_state() {
        let (mut writer, mut reader) = (bind(), bind());
        let reader_addr = reader.listen().expect("reader listens");
        let reader_peer = *reader.peer_id();
        writer.connect(&reader_addr).expect("connect");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !writer.is_peer_ready(&reader_peer) {
            assert!(Instant::now() < deadline, "peers never became ready");
            let _ = (step(&mut writer), step(&mut reader));
        }
        let stream = writer
            .open_stream(&reader_peer, PROTOCOL)
            .expect("open stream");
        loop {
            assert!(Instant::now() < deadline, "stream never negotiated");
            let _ = step(&mut reader);
            if let Some(EndpointEvent::StreamReady { stream: ready, .. }) = step(&mut writer)
                && ready == stream
            {
                break;
            }
        }

        // Past every send cap, so the tail is held and the FIN deferred.
        let accepted = send_whole(&mut writer, stream, vec![0; 4 << 20]).expect("write");
        assert!(!accepted);
        assert!(matches!(
            send_whole(&mut writer, stream, vec![1]),
            Err(FfiError::Backpressure)
        ));
        writer.close_stream_write(stream).expect("deferred close");
        assert!(matches!(
            send_whole(&mut writer, stream, vec![1]),
            Err(FfiError::InvalidState { .. })
        ));
    }
}
