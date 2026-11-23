//! Unit tests for the RTT benches' emulated link (`benches/support/delay.rs`),
//! which run here because the benches are `harness = false`.

#[expect(
    dead_code,
    reason = "the benches use the link, the tests only its calibration"
)]
#[path = "../benches/support/delay.rs"]
mod delay;
