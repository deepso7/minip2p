//! Sans-IO STUN Binding client helpers.
//!
//! This crate contains only packet construction and parsing. Runtime concerns
//! such as UDP sockets, DNS, retries, clocks, and random transaction IDs belong
//! to transport adapters or applications.
//!
//! `no_std` compatible.

#![cfg_attr(not(feature = "std"), no_std)]

use core::net::{IpAddr, SocketAddr};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const HEADER_LEN: usize = 20;

/// Length in bytes of a STUN transaction ID.
pub const TRANSACTION_ID_LEN: usize = 12;

/// A STUN Binding client for one transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingClient {
    transaction_id: [u8; TRANSACTION_ID_LEN],
}

impl BindingClient {
    /// Creates a client for a caller-provided transaction ID.
    ///
    /// Transaction ID generation is runtime-owned so this crate stays Sans-IO
    /// and does not depend on a random source.
    pub fn new(transaction_id: [u8; TRANSACTION_ID_LEN]) -> Self {
        Self { transaction_id }
    }

    /// Returns the transaction ID this client expects responses to echo.
    pub fn transaction_id(&self) -> &[u8; TRANSACTION_ID_LEN] {
        &self.transaction_id
    }

    /// Builds a STUN Binding Request packet.
    pub fn binding_request(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        out[2..4].copy_from_slice(&0u16.to_be_bytes());
        out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out[8..20].copy_from_slice(&self.transaction_id);
        out
    }

    /// Parses a possible Binding Success Response.
    ///
    /// Returns `Ok(None)` for packets that are not a success response for this
    /// transaction. Returns `Ok(Some(addr))` when a mapped address is present.
    pub fn parse_response(&self, packet: &[u8]) -> Result<Option<SocketAddr>, StunError> {
        if packet.len() < HEADER_LEN {
            return Ok(None);
        }
        if u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS_RESPONSE {
            return Ok(None);
        }

        let body_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if packet.len() < HEADER_LEN + body_len {
            return Err(StunError::TruncatedMessage {
                declared_len: body_len,
                actual_len: packet.len().saturating_sub(HEADER_LEN),
            });
        }
        if u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != MAGIC_COOKIE {
            return Ok(None);
        }
        if &packet[8..20] != self.transaction_id.as_slice() {
            return Ok(None);
        }

        let mut offset = HEADER_LEN;
        let end = HEADER_LEN + body_len;
        let mut mapped = None;
        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            let attr_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            offset += 4;
            if offset + attr_len > end {
                return Err(StunError::TruncatedAttribute {
                    attr_type,
                    declared_len: attr_len,
                });
            }

            let value = &packet[offset..offset + attr_len];
            match attr_type {
                XOR_MAPPED_ADDRESS => {
                    return parse_address(value, true, &self.transaction_id).map(Some);
                }
                MAPPED_ADDRESS => {
                    mapped = Some(parse_address(value, false, &self.transaction_id)?);
                }
                _ => {}
            }

            offset += (attr_len + 3) & !3;
        }

        Ok(mapped)
    }
}

/// STUN packet parse errors.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StunError {
    /// The message body is shorter than the STUN header declares.
    #[error("STUN message body truncated: declared {declared_len} bytes, got {actual_len}")]
    TruncatedMessage {
        /// Declared body length from the STUN header.
        declared_len: usize,
        /// Actual bytes available after the STUN header.
        actual_len: usize,
    },
    /// An attribute length extends beyond the message body.
    #[error("STUN attribute 0x{attr_type:04x} truncated: declared {declared_len} bytes")]
    TruncatedAttribute {
        /// Attribute type code.
        attr_type: u16,
        /// Declared value length.
        declared_len: usize,
    },
    /// A mapped-address attribute had an invalid shape.
    #[error("invalid STUN mapped-address attribute")]
    InvalidMappedAddress,
}

fn parse_address(
    value: &[u8],
    xor: bool,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidMappedAddress);
    }

    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }

    match value[1] {
        0x01 => parse_ipv4(value, xor, port),
        0x02 => parse_ipv6(value, xor, port, transaction_id),
        _ => Err(StunError::InvalidMappedAddress),
    }
}

fn parse_ipv4(value: &[u8], xor: bool, port: u16) -> Result<SocketAddr, StunError> {
    if value.len() < 8 {
        return Err(StunError::InvalidMappedAddress);
    }
    let mut ip = [value[4], value[5], value[6], value[7]];
    if xor {
        let cookie = MAGIC_COOKIE.to_be_bytes();
        for (byte, mask) in ip.iter_mut().zip(cookie) {
            *byte ^= mask;
        }
    }
    Ok(SocketAddr::new(IpAddr::from(ip), port))
}

fn parse_ipv6(
    value: &[u8],
    xor: bool,
    port: u16,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Result<SocketAddr, StunError> {
    if value.len() < 20 {
        return Err(StunError::InvalidMappedAddress);
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&value[4..20]);
    if xor {
        let mut mask = [0u8; 16];
        mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        mask[4..].copy_from_slice(transaction_id);
        for (byte, mask) in ip.iter_mut().zip(mask) {
            *byte ^= mask;
        }
    }
    Ok(SocketAddr::new(IpAddr::from(ip), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_binding_request() {
        let tx = [7u8; TRANSACTION_ID_LEN];
        let request = BindingClient::new(tx).binding_request();

        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]),
            BINDING_REQUEST
        );
        assert_eq!(u16::from_be_bytes([request[2], request[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&request[8..20], tx);
    }

    #[test]
    fn parses_xor_mapped_ipv4_response() {
        let tx = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let expected_ip = [203, 0, 113, 9];
        let expected_port = 44_321u16;
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let xport = expected_port ^ ((MAGIC_COOKIE >> 16) as u16);
        let xip = [
            expected_ip[0] ^ cookie[0],
            expected_ip[1] ^ cookie[1],
            expected_ip[2] ^ cookie[2],
            expected_ip[3] ^ cookie[3],
        ];

        let packet = response_packet(
            &tx,
            XOR_MAPPED_ADDRESS,
            &[
                0,
                0x01,
                xport.to_be_bytes()[0],
                xport.to_be_bytes()[1],
                xip[0],
                xip[1],
                xip[2],
                xip[3],
            ],
        );

        let parsed = BindingClient::new(tx)
            .parse_response(&packet)
            .expect("response should parse")
            .expect("mapped addr should exist");
        assert_eq!(
            parsed,
            SocketAddr::new(IpAddr::from(expected_ip), expected_port)
        );
    }

    #[test]
    fn ignores_wrong_transaction_id() {
        let packet = response_packet(&[1u8; TRANSACTION_ID_LEN], XOR_MAPPED_ADDRESS, &[0; 8]);
        assert_eq!(
            BindingClient::new([2u8; TRANSACTION_ID_LEN]).parse_response(&packet),
            Ok(None)
        );
    }

    fn response_packet(
        tx: &[u8; TRANSACTION_ID_LEN],
        attr_type: u16,
        attr_value: &[u8],
    ) -> Vec<u8> {
        let body_len = 4 + attr_value.len();
        let mut packet = Vec::new();
        packet.extend_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
        packet.extend_from_slice(&(body_len as u16).to_be_bytes());
        packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(tx);
        packet.extend_from_slice(&attr_type.to_be_bytes());
        packet.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        packet.extend_from_slice(attr_value);
        packet
    }
}
