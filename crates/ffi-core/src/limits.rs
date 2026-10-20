//! Applies [`LimitsOptions`] onto the native transport limits.

use minip2p::{CircuitLimits, NatConfig, QuicLimits, TcpConfig, YamuxConfig};

use crate::{
    ConfigCapability, FfiError, LimitsOptions, QuicLimitsOptions, TcpLimitsOptions, TimeoutLimit,
    WindowLimit, YamuxOptions,
};

/// The native limits an endpoint binds with.
#[derive(Debug)]
pub(crate) struct Limits {
    pub(crate) quic: QuicLimits,
    pub(crate) tcp: TcpConfig,
    pub(crate) circuit: CircuitLimits,
    pub(crate) max_circuits: usize,
}

/// Overlays `options` on the native defaults. Values are not validated here:
/// the endpoint does that for the transports it binds. A value too large for
/// this platform's `usize` is rejected, never truncated.
pub(crate) fn resolve_limits(options: Option<LimitsOptions>) -> Result<Limits, FfiError> {
    let options = options.unwrap_or_default();
    let mut limits = Limits {
        quic: QuicLimits::default(),
        tcp: TcpConfig::default(),
        circuit: CircuitLimits::default(),
        max_circuits: NatConfig::default().max_circuits,
    };
    if let Some(quic) = options.quic {
        apply_quic(&mut limits.quic, quic)?;
    }
    if let Some(tcp) = options.tcp {
        apply_tcp(&mut limits.tcp, tcp)?;
    }
    if let Some(circuit) = options.circuit {
        apply_yamux(&mut limits.circuit.yamux, circuit, "limits.circuit")?;
    }
    set_usize(
        &mut limits.max_circuits,
        options.max_circuits,
        "limits.max_circuits",
    )?;
    Ok(limits)
}

fn apply_quic(limits: &mut QuicLimits, options: QuicLimitsOptions) -> Result<(), FfiError> {
    set_usize(
        &mut limits.max_connections,
        options.max_connections,
        "limits.quic.max_connections",
    )?;
    set(
        &mut limits.max_streams_per_connection,
        options.max_streams_per_connection,
    );
    set_usize(
        &mut limits.max_pending_bytes_per_stream,
        options.max_pending_bytes_per_stream,
        "limits.quic.max_pending_bytes_per_stream",
    )?;
    set_usize(
        &mut limits.max_pending_connection_bytes,
        options.max_pending_connection_bytes,
        "limits.quic.max_pending_connection_bytes",
    )?;
    set_usize(
        &mut limits.control_stream_reserve_bytes,
        options.control_stream_reserve_bytes,
        "limits.quic.control_stream_reserve_bytes",
    )?;
    set_usize(
        &mut limits.max_pending_datagrams,
        options.max_pending_datagrams,
        "limits.quic.max_pending_datagrams",
    )?;
    set(&mut limits.idle_timeout_ms, options.idle_timeout_ms);
    set(
        &mut limits.require_address_validation,
        options.require_address_validation,
    );
    set_usize(
        &mut limits.stream_receive_window,
        options.stream_receive_window,
        "limits.quic.stream_receive_window",
    )?;
    match options.connection_receive_window {
        None => {}
        Some(WindowLimit::Unlimited) => limits.connection_receive_window = usize::MAX,
        Some(WindowLimit::Bounded { bytes }) => set_usize(
            &mut limits.connection_receive_window,
            Some(bytes),
            "limits.quic.connection_receive_window",
        )?,
    }
    set_usize(
        &mut limits.send_window,
        options.send_window,
        "limits.quic.send_window",
    )?;
    set(
        &mut limits.webtransport_handshake_timeout_ms,
        options.webtransport_handshake_timeout_ms,
    );
    Ok(())
}

fn apply_tcp(config: &mut TcpConfig, options: TcpLimitsOptions) -> Result<(), FfiError> {
    set_usize(
        &mut config.max_connections,
        options.max_connections,
        "limits.tcp.max_connections",
    )?;
    set(
        &mut config.handshake_timeout_ms,
        options.handshake_timeout_ms.map(TimeoutLimit::millis),
    );
    set_usize(
        &mut config.max_buffered_send,
        options.max_buffered_send,
        "limits.tcp.max_buffered_send",
    )?;
    set(
        &mut config.send_stall_timeout_ms,
        options.send_stall_timeout_ms.map(TimeoutLimit::millis),
    );
    if let Some(yamux) = options.yamux {
        apply_yamux(&mut config.yamux, yamux, "limits.tcp.yamux")?;
    }
    Ok(())
}

/// Overlays Yamux options; `path` prefixes the field an overflow names.
fn apply_yamux(
    config: &mut YamuxConfig,
    options: YamuxOptions,
    path: &str,
) -> Result<(), FfiError> {
    let field = |name: &str| format!("{path}.{name}");
    set(&mut config.receive_window, options.receive_window);
    set(&mut config.max_frame_len, options.max_frame_len);
    set_usize(
        &mut config.max_streams,
        options.max_streams,
        &field("max_streams"),
    )?;
    set_usize(
        &mut config.max_buffered_send,
        options.max_buffered_send,
        &field("max_buffered_send"),
    )?;
    set_usize(
        &mut config.max_total_buffered_send,
        options.max_total_buffered_send,
        &field("max_total_buffered_send"),
    )?;
    set_usize(
        &mut config.control_stream_reserve,
        options.control_stream_reserve,
        &field("control_stream_reserve"),
    )?;
    set_usize(
        &mut config.max_pending_control,
        options.max_pending_control,
        &field("max_pending_control"),
    )?;
    Ok(())
}

impl TimeoutLimit {
    /// The native form: `None` waits indefinitely.
    fn millis(self) -> Option<u64> {
        match self {
            Self::AfterMs { ms } => Some(ms),
            Self::Never => None,
        }
    }
}

/// Sets `target` when the caller supplied a value.
fn set<T>(target: &mut T, value: Option<T>) {
    if let Some(value) = value {
        *target = value;
    }
}

/// Sets a `usize` limit from a foreign `u64`, rejecting one that does not fit.
fn set_usize(target: &mut usize, value: Option<u64>, field: &str) -> Result<(), FfiError> {
    if let Some(value) = value {
        *target = checked(value, field)?;
    }
    Ok(())
}

/// Converts a foreign `u64` to the native width (`usize` outside tests).
fn checked<T: TryFrom<u64>>(value: u64, field: &str) -> Result<T, FfiError> {
    T::try_from(value).map_err(|_overflow| FfiError::InvalidConfig {
        capability: ConfigCapability::Transport,
        detail: format!("{field} ({value}) exceeds this platform's usize range"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_defaults(limits: &Limits) {
        assert_eq!(
            format!("{:?}", limits.quic),
            format!("{:?}", QuicLimits::default())
        );
        assert_eq!(limits.tcp, TcpConfig::default());
        assert_eq!(limits.circuit, CircuitLimits::default());
        assert_eq!(limits.max_circuits, 64);
    }

    #[test]
    fn omitted_and_empty_limits_keep_the_native_defaults() {
        for options in [
            None,
            Some(LimitsOptions::default()),
            Some(LimitsOptions {
                quic: Some(QuicLimitsOptions::default()),
                tcp: Some(TcpLimitsOptions {
                    yamux: Some(YamuxOptions::default()),
                    ..TcpLimitsOptions::default()
                }),
                circuit: Some(YamuxOptions::default()),
                max_circuits: None,
            }),
        ] {
            assert_defaults(&resolve_limits(options).expect("limits"));
        }
    }

    #[test]
    fn a_partial_override_changes_only_its_field() {
        let limits = resolve_limits(Some(LimitsOptions {
            quic: Some(QuicLimitsOptions {
                stream_receive_window: Some(4_000_000),
                ..QuicLimitsOptions::default()
            }),
            ..LimitsOptions::default()
        }))
        .expect("limits");

        let expected = QuicLimits {
            stream_receive_window: 4_000_000,
            ..QuicLimits::default()
        };
        assert_eq!(format!("{:?}", limits.quic), format!("{expected:?}"));
        assert_eq!(limits.tcp, TcpConfig::default());
    }

    #[test]
    fn unlimited_windows_and_never_timeouts_map_to_the_native_forms() {
        let resolve = |window, timeout| {
            resolve_limits(Some(LimitsOptions {
                quic: Some(QuicLimitsOptions {
                    connection_receive_window: Some(window),
                    ..QuicLimitsOptions::default()
                }),
                tcp: Some(TcpLimitsOptions {
                    handshake_timeout_ms: Some(timeout),
                    send_stall_timeout_ms: Some(timeout),
                    ..TcpLimitsOptions::default()
                }),
                ..LimitsOptions::default()
            }))
            .expect("limits")
        };

        let open = resolve(WindowLimit::Unlimited, TimeoutLimit::Never);
        assert_eq!(open.quic.connection_receive_window, usize::MAX);
        assert_eq!(open.tcp.handshake_timeout_ms, None);
        assert_eq!(open.tcp.send_stall_timeout_ms, None);

        let bounded = resolve(
            WindowLimit::Bounded { bytes: 8_000_000 },
            TimeoutLimit::AfterMs { ms: 5_000 },
        );
        assert_eq!(bounded.quic.connection_receive_window, 8_000_000);
        assert_eq!(bounded.tcp.handshake_timeout_ms, Some(5_000));
        assert_eq!(bounded.tcp.send_stall_timeout_ms, Some(5_000));
    }

    #[test]
    fn tcp_and_circuit_yamux_limits_are_independent() {
        let window = |receive_window| YamuxOptions {
            receive_window: Some(receive_window),
            ..YamuxOptions::default()
        };
        let tcp_only = resolve_limits(Some(LimitsOptions {
            tcp: Some(TcpLimitsOptions {
                yamux: Some(window(1 << 20)),
                ..TcpLimitsOptions::default()
            }),
            ..LimitsOptions::default()
        }))
        .expect("limits");
        assert_eq!(tcp_only.tcp.yamux.receive_window, 1 << 20);
        assert_eq!(tcp_only.circuit, CircuitLimits::default());

        let circuit_only = resolve_limits(Some(LimitsOptions {
            circuit: Some(window(2 << 20)),
            max_circuits: Some(8),
            ..LimitsOptions::default()
        }))
        .expect("limits");
        assert_eq!(circuit_only.circuit.yamux.receive_window, 2 << 20);
        assert_eq!(circuit_only.max_circuits, 8);
        assert_eq!(circuit_only.tcp, TcpConfig::default());
    }

    #[test]
    fn a_value_past_the_native_range_is_rejected_not_truncated() {
        // `usize` is 64 bits here, so check the conversion against `u32`, as
        // a 32-bit platform's `usize` would be.
        let error = checked::<u32>(u64::from(u32::MAX) + 1, "limits.quic.send_window")
            .expect_err("overflow");
        assert!(matches!(
            error,
            FfiError::InvalidConfig {
                capability: ConfigCapability::Transport,
                ref detail,
            } if detail.contains("limits.quic.send_window")
        ));
        assert_eq!(
            checked::<u32>(u64::from(u32::MAX), "f").ok(),
            Some(u32::MAX)
        );
    }
}
