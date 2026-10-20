//! [`WebTransportIo`] over the TypeScript `JsIo` (`bindings/ts/web/src/io.ts`),
//! which owns the browser's `WebTransport` objects.
//!
//! Every call returns at once. `write` hands JS a view into wasm memory that
//! `JsIo` copies before returning, so a queued browser write never points at
//! memory that may move. Promise outcomes come back through `pollEvent` as
//! plain `{ kind, ... }` objects, decoded here.

use minip2p_core::{Bytes, Multihash};
use minip2p_webtransport::{IoError, IoEvent, SessionHandle, StreamHandle, WebTransportIo};
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// The TypeScript `JsIo`: the `WebTransportIo` contract over the
    /// browser API, with handles as numbers.
    pub type JsIoHandle;

    #[wasm_bindgen(method, catch)]
    fn connect(this: &JsIoHandle, url: &str, certhashes: js_sys::Array) -> Result<u32, JsValue>;

    #[wasm_bindgen(method, catch, js_name = openStream)]
    fn open_stream(this: &JsIoHandle, session: u32) -> Result<u32, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn write(this: &JsIoHandle, stream: u32, data: &[u8]) -> Result<u32, JsValue>;

    #[wasm_bindgen(method, js_name = closeWrite)]
    fn close_write(this: &JsIoHandle, stream: u32);

    #[wasm_bindgen(method)]
    fn reset(this: &JsIoHandle, stream: u32, code: u8);

    #[wasm_bindgen(method)]
    fn stop(this: &JsIoHandle, stream: u32, code: u8);

    #[wasm_bindgen(method, js_name = grantRead)]
    fn grant_read(this: &JsIoHandle, stream: u32, bytes: u32);

    #[wasm_bindgen(method)]
    fn close(this: &JsIoHandle, session: u32, code: u32, reason: &str);

    #[wasm_bindgen(method, js_name = pollEvent)]
    fn poll_event(this: &JsIoHandle) -> JsValue;
}

/// One event `JsIo.pollEvent` returns; mirrors [`IoEvent`].
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum JsEvent {
    SessionReady {
        session: u32,
    },
    SessionClosed {
        session: u32,
        code: u32,
        reason: String,
    },
    SessionFailed {
        session: u32,
        reason: String,
    },
    StreamOpened {
        stream: u32,
    },
    IncomingStream {
        session: u32,
        stream: u32,
    },
    Data {
        stream: u32,
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    Fin {
        stream: u32,
    },
    Reset {
        stream: u32,
        code: u8,
    },
    StopSending {
        stream: u32,
        code: u8,
    },
    WriteCompleted {
        stream: u32,
        bytes: u32,
    },
}

impl From<JsEvent> for IoEvent {
    fn from(event: JsEvent) -> Self {
        let session = |id: u32| SessionHandle(id.into());
        let stream = |id: u32| StreamHandle(id.into());
        match event {
            JsEvent::SessionReady { session: id } => Self::SessionReady {
                session: session(id),
            },
            JsEvent::SessionClosed {
                session: id,
                code,
                reason,
            } => Self::SessionClosed {
                session: session(id),
                code,
                reason,
            },
            JsEvent::SessionFailed {
                session: id,
                reason,
            } => Self::SessionFailed {
                session: session(id),
                reason,
            },
            JsEvent::StreamOpened { stream: id } => Self::StreamOpened { stream: stream(id) },
            JsEvent::IncomingStream {
                session: sid,
                stream: id,
            } => Self::IncomingStream {
                session: session(sid),
                stream: stream(id),
            },
            JsEvent::Data { stream: id, bytes } => Self::Data {
                stream: stream(id),
                bytes: Bytes::from(bytes),
            },
            JsEvent::Fin { stream: id } => Self::Fin { stream: stream(id) },
            JsEvent::Reset { stream: id, code } => Self::Reset {
                stream: stream(id),
                code,
            },
            JsEvent::StopSending { stream: id, code } => Self::StopSending {
                stream: stream(id),
                code,
            },
            JsEvent::WriteCompleted { stream: id, bytes } => Self::WriteCompleted {
                stream: stream(id),
                bytes: bytes as usize,
            },
        }
    }
}

/// The client's I/O: the TypeScript `JsIo` behind its wasm-bindgen handle.
pub(crate) struct JsIo(pub(crate) JsIoHandle);

impl WebTransportIo for JsIo {
    fn connect(&mut self, url: &str, certhashes: &[Multihash]) -> Result<SessionHandle, IoError> {
        let digests: js_sys::Array = certhashes
            .iter()
            .map(|hash| js_sys::Uint8Array::from(hash.digest()))
            .collect();
        self.0
            .connect(url, digests)
            .map(|id| SessionHandle(id.into()))
            .map_err(io_error)
    }

    fn open_stream(&mut self, session: SessionHandle) -> Result<StreamHandle, IoError> {
        self.0
            .open_stream(js_handle(session.0))
            .map(|id| StreamHandle(id.into()))
            .map_err(io_error)
    }

    fn write(&mut self, stream: StreamHandle, data: &[u8]) -> Result<usize, IoError> {
        self.0
            .write(js_handle(stream.0), data)
            .map(|accepted| accepted as usize)
            .map_err(io_error)
    }

    fn close_write(&mut self, stream: StreamHandle) {
        self.0.close_write(js_handle(stream.0));
    }

    fn reset(&mut self, stream: StreamHandle, code: u8) {
        self.0.reset(js_handle(stream.0), code);
    }

    fn stop(&mut self, stream: StreamHandle, code: u8) {
        self.0.stop(js_handle(stream.0), code);
    }

    fn grant_read(&mut self, stream: StreamHandle, bytes: usize) {
        self.0.grant_read(
            js_handle(stream.0),
            u32::try_from(bytes).unwrap_or(u32::MAX),
        );
    }

    fn close(&mut self, session: SessionHandle, code: u32, reason: &str) {
        self.0.close(js_handle(session.0), code, reason);
    }

    fn poll_event(&mut self) -> Option<IoEvent> {
        loop {
            let value = self.0.poll_event();
            if value.is_undefined() || value.is_null() {
                return None;
            }
            // `JsIo` is ours; an event it cannot shape is skipped rather
            // than ending the endpoint.
            if let Ok(event) = serde_wasm_bindgen::from_value::<JsEvent>(value) {
                return Some(event.into());
            }
        }
    }
}

/// Handles come from `JsIo` as `u32`s, so every one the client holds fits.
fn js_handle(handle: u64) -> u32 {
    u32::try_from(handle).unwrap_or(u32::MAX)
}

fn io_error(error: JsValue) -> IoError {
    let message = error
        .dyn_ref::<js_sys::Error>()
        .map(|error| String::from(error.message()))
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "the WebTransport call failed".into());
    IoError(message)
}
