//! Shared ownership of one [smoltcp] network stack.
//!
//! A smoltcp [`Device`], [`Interface`], and [`SocketSet`] form one indivisible
//! network stack. [`SmoltcpStack`] lets independent minip2p adapters install
//! their protocol sockets into that stack without either adapter claiming the
//! physical link exclusively.

#![no_std]

extern crate alloc;

use alloc::{rc::Rc, vec::Vec};
use core::cell::{Ref, RefCell, RefMut};

use smoltcp::iface::{Interface, SocketSet};
use smoltcp::phy::Device;

pub use smoltcp;

/// The device, interface, and sockets making up one smoltcp network stack.
///
/// Adapters normally access this through [`SmoltcpStack::borrow_mut`]. The
/// fields are public so an adapter can pass the three disjoint borrows to
/// smoltcp without this crate having to mirror its API.
pub struct SmoltcpStackState<D: Device> {
    /// Physical or virtual link device.
    pub device: D,
    /// Addressing and protocol interface.
    pub interface: Interface,
    /// Socket collection shared by every adapter on the stack.
    pub sockets: SocketSet<'static>,
}

/// Cloneable handle to one caller-driven smoltcp network stack.
///
/// The handle is intentionally single-threaded: embedded event loops drive
/// their stack serially, and avoiding synchronization keeps the contract
/// available on targets without atomics.
pub struct SmoltcpStack<D: Device> {
    inner: Rc<RefCell<SmoltcpStackState<D>>>,
}

impl<D: Device> Clone for SmoltcpStack<D> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<D: Device> SmoltcpStack<D> {
    /// Creates an empty socket set over a host-configured interface and link.
    pub fn new(device: D, interface: Interface) -> Self {
        Self {
            inner: Rc::new(RefCell::new(SmoltcpStackState {
                device,
                interface,
                sockets: SocketSet::new(Vec::new()),
            })),
        }
    }

    /// Borrows the shared stack for inspection.
    pub fn borrow(&self) -> Ref<'_, SmoltcpStackState<D>> {
        self.inner.borrow()
    }

    /// Borrows the shared stack for one adapter operation.
    ///
    /// Holding this guard while calling another adapter on the same stack is a
    /// programming error. Endpoint drivers avoid that by polling adapters
    /// serially.
    pub fn borrow_mut(&self) -> RefMut<'_, SmoltcpStackState<D>> {
        self.inner.borrow_mut()
    }
}
