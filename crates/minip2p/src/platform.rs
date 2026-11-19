//! What an [`Endpoint`](crate::Endpoint) is generic over: the platform that
//! supplies the few things that differ between hosts (ADR 0029).
//!
//! Everything else (the engine, its event stream, every endpoint method
//! that does not need an operating system) is implemented once, on
//! `Endpoint<P>`. A platform supplies:
//!
//! - the clock every endpoint call samples,
//! - its transport and entropy types (the transports it binds),
//! - Name resolution for `/dns*` candidates, and
//! - the readiness collection a non-blocking `poll` runs first (the std
//!   platform also adds the blocking `wait` on top).
//!
//! [`Platform`] is sealed: the two platforms are the std one (`StdPlatform`,
//! behind the `std` feature and the default for `Endpoint`) and
//! [`Portable`], which runs over any caller-supplied transport, entropy
//! source and [`Clock`].

use core::marker::PhantomData;

use minip2p_core::platform::{Clock, EntropySource, Now};
use minip2p_swarm::DriverError;
use minip2p_transport::Transport;

use crate::engine::Carrier;
use crate::names::{Concrete, Expander};

/// The host an [`Endpoint`](crate::Endpoint) runs on: `StdPlatform` (the
/// default under `std`) or [`Portable`] (ADR 0029).
///
/// A platform supplies only what differs between hosts: the clock every
/// endpoint call samples, its transport and entropy types, Name resolution
/// for `/dns*` candidates, and the readiness collection a non-blocking
/// `poll` runs first. Everything else is implemented once, on
/// `Endpoint<P>`. Sealed: no other platform can be implemented.
pub trait Platform: sealed::Sealed {}

pub(crate) mod sealed {
    use super::*;

    /// What the engine needs from its platform. Public only inside this
    /// private module, so no other crate can name or implement it.
    pub trait Sealed: Sized {
        /// The transport the engine drives.
        type Transport: Transport;
        /// The swarm's entropy source.
        type Entropy: EntropySource;
        /// The mDNS carrier (`()` without mDNS).
        type Carrier: Carrier;
        /// Samples the clock; every engine call takes one sample.
        fn now(&mut self) -> Now;
        /// Candidate expansion: Name resolution on std, concrete addresses
        /// only on a portable platform.
        fn names(&mut self) -> &mut dyn Expander;
        /// Collects readiness without blocking before a drive; a no-op for a
        /// platform whose transport reads its own input when polled.
        fn harvest(&mut self, transport: &mut Self::Transport) -> Result<(), DriverError>;
        /// The platform's teardown behind `Endpoint::close`.
        fn close(endpoint: crate::Endpoint<Self>) -> crate::CloseReport
        where
            Self: super::Platform;
    }
}

/// The portable platform: any [`Transport`] `T`, entropy source `E`, and
/// caller-supplied [`Clock`] `C`.
///
/// It owns no clock, executor, sockets, or operating-system entropy source:
/// the clock is the host's (a hardware timer on a microcontroller,
/// `performance.now()` in a browser, a manual clock in a deterministic
/// simulation), and every endpoint call samples it once. Names are not
/// resolved: `/dns*` candidates fail as unusable.
///
/// Built with [`PortableEndpointBuilder`](crate::PortableEndpointBuilder);
/// [`PortableEndpoint`](crate::PortableEndpoint) names the endpoint type.
pub struct Portable<T, E, C> {
    clock: C,
    names: Concrete,
    _types: PhantomData<fn() -> (T, E)>,
}

impl<T, E, C> Portable<T, E, C> {
    pub(crate) fn new(clock: C) -> Self {
        Self {
            clock,
            names: Concrete,
            _types: PhantomData,
        }
    }

    pub(crate) fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }
}

/// The mDNS carrier a portable endpoint holds: any caller-owned `MdnsIo`.
#[cfg(feature = "mdns")]
pub(crate) type PortableCarrier = alloc::boxed::Box<dyn minip2p_mdns::MdnsIo>;
#[cfg(not(feature = "mdns"))]
pub(crate) type PortableCarrier = ();

impl<T: Transport, E: EntropySource, C: Clock> sealed::Sealed for Portable<T, E, C> {
    type Transport = T;
    type Entropy = E;
    type Carrier = PortableCarrier;

    fn now(&mut self) -> Now {
        self.clock.now()
    }

    fn names(&mut self) -> &mut dyn Expander {
        &mut self.names
    }

    fn harvest(&mut self, _transport: &mut T) -> Result<(), DriverError> {
        Ok(())
    }

    fn close(endpoint: crate::Endpoint<Self>) -> crate::CloseReport {
        endpoint.close_portable()
    }
}

impl<T: Transport, E: EntropySource, C: Clock> Platform for Portable<T, E, C> {}
