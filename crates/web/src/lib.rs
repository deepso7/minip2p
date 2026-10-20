//! wasm-bindgen shell for minip2p in the browser.
//!
//! Two layers:
//!
//! - [`Host`] is the browser endpoint itself: a
//!   [`PortableEndpoint`](minip2p::PortableEndpoint) behind ffi-core's
//!   thread-free host core, with the commands and event stream of ffi-core's
//!   `P2pEndpoint`. It never touches wasm, so it is tested natively.
//! - [`WebEndpoint`] (wasm32 only) exposes the host to JavaScript with the
//!   same surface as the Node addon's `NodeEndpoint`, over a
//!   [`WebTransportClient`](minip2p_webtransport::WebTransportClient) whose
//!   I/O is the TypeScript `JsIo` (`bindings/ts/web/src/io.ts`).
//!
//! There is no thread and no async: the TypeScript adapter schedules
//! `pump`, and the browser's promises become queued I/O events the client
//! drains as it is polled. Time comes from `performance.now()` and
//! `Date.now()`; std's clock is never compiled in, since `Instant` panics on
//! wasm32. Entropy is `crypto.getRandomValues` through getrandom.

#![warn(missing_docs)]

mod host;
#[cfg(target_arch = "wasm32")]
mod io;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use host::{Host, Pumped};
#[cfg(target_arch = "wasm32")]
pub use wasm::WebEndpoint;

use minip2p::EntropySource;
use minip2p_core::platform::EntropyError;

/// The platform's cryptographic random source (`crypto.getRandomValues` in
/// a browser, the OS natively).
#[derive(Clone, Copy, Debug, Default)]
pub struct WebEntropy;

impl EntropySource for WebEntropy {
    fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(output)
            .map_err(|_error| EntropyError::failed("crypto.getRandomValues failed"))
    }
}
