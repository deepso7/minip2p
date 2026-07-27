//! Bounded DNS codec for the libp2p mDNS subset.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

/// libp2p mDNS service name.
pub const SERVICE_NAME: &str = "_p2p._udp.local";
/// DNS-SD meta-query name.
pub const META_QUERY_NAME: &str = "_services._dns-sd._udp.local";
/// DNS class IN.
pub const CLASS_IN: u16 = 1;
/// DNS PTR record type.
pub const TYPE_PTR: u16 = 12;
/// DNS TXT record type.
pub const TYPE_TXT: u16 = 16;
/// Largest datagram accepted by the decoder.
pub const MDNS_MAX_DECODE_BYTES: usize = 9_000;

const FLAG_QR: u16 = 0x8000;
const FLAG_AA: u16 = 0x0400;
const CLASS_HIGH_BIT: u16 = 0x8000;
const MAX_POINTER_JUMPS: usize = 32;

/// One decoded DNS question.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    /// Dot-separated owner name without a trailing dot.
    pub name: String,
    /// Numeric DNS question type.
    pub qtype: u16,
    /// Raw class, including the mDNS QU bit.
    pub class: u16,
}

impl DnsQuestion {
    /// Returns whether the mDNS unicast-response bit is set.
    pub const fn requests_unicast(&self) -> bool {
        self.class & CLASS_HIGH_BIT != 0
    }

    /// Returns the class with the mDNS high bit removed.
    pub const fn base_class(&self) -> u16 {
        self.class & !CLASS_HIGH_BIT
    }
}

/// Supported decoded DNS record payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRecordData {
    /// A decoded domain name from PTR RDATA.
    Ptr(String),
    /// All character-strings carried by one TXT RDATA.
    Txt(Vec<Vec<u8>>),
}

/// One supported decoded DNS resource record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    /// Dot-separated owner name without a trailing dot.
    pub name: String,
    /// Numeric DNS record type.
    pub rr_type: u16,
    /// Raw class, including the mDNS cache-flush bit.
    pub class: u16,
    /// Record lifetime in seconds.
    pub ttl: u32,
    /// Decoded supported payload.
    pub data: DnsRecordData,
}

impl DnsRecord {
    /// Returns whether the mDNS cache-flush bit is set.
    pub const fn cache_flush(&self) -> bool {
        self.class & CLASS_HIGH_BIT != 0
    }

    /// Returns the class with the mDNS high bit removed.
    pub const fn base_class(&self) -> u16 {
        self.class & !CLASS_HIGH_BIT
    }
}

/// A bounded decoded DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsMessage {
    /// DNS transaction id.
    pub id: u16,
    /// Raw DNS flags.
    pub flags: u16,
    /// Questions in wire order.
    pub questions: Vec<DnsQuestion>,
    /// Supported records from the answer section.
    pub answers: Vec<DnsRecord>,
    /// Supported records from the authority section.
    pub authorities: Vec<DnsRecord>,
    /// Supported records from the additional section.
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    /// Decodes one complete DNS datagram with strict allocation and pointer bounds.
    pub fn decode(packet: &[u8]) -> Result<Self, DnsCodecError> {
        if packet.len() > MDNS_MAX_DECODE_BYTES {
            return Err(DnsCodecError::PacketTooLarge);
        }
        if packet.len() < 12 {
            return Err(DnsCodecError::Truncated);
        }
        let id = read_u16(packet, 0)?;
        let flags = read_u16(packet, 2)?;
        let question_count = read_u16(packet, 4)? as usize;
        let answer_count = read_u16(packet, 6)? as usize;
        let authority_count = read_u16(packet, 8)? as usize;
        let additional_count = read_u16(packet, 10)? as usize;
        let mut cursor = 12;
        let mut questions = Vec::with_capacity(question_count.min(32));
        for _ in 0..question_count {
            let name = decode_name(packet, &mut cursor)?;
            let qtype = take_u16(packet, &mut cursor)?;
            let class = take_u16(packet, &mut cursor)?;
            questions.push(DnsQuestion { name, qtype, class });
        }
        let answers = decode_records(packet, &mut cursor, answer_count)?;
        let authorities = decode_records(packet, &mut cursor, authority_count)?;
        let additionals = decode_records(packet, &mut cursor, additional_count)?;
        if cursor != packet.len() {
            return Err(DnsCodecError::TrailingBytes);
        }
        Ok(Self {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    /// Returns whether the DNS QR bit marks this as a response.
    pub const fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }

    /// Returns the decoded four-bit DNS opcode.
    pub const fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }

    /// Returns the decoded four-bit DNS response code.
    pub const fn rcode(&self) -> u8 {
        (self.flags & 0x0f) as u8
    }
}

/// A malformed or unsupported DNS wire input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DnsCodecError {
    /// The datagram exceeds the decoder's hard cap.
    #[error("DNS packet exceeds 9000 bytes")]
    PacketTooLarge,
    /// A field or section extends beyond the datagram.
    #[error("truncated DNS packet")]
    Truncated,
    /// A DNS label exceeds 63 bytes.
    #[error("DNS label exceeds 63 bytes")]
    LabelTooLong,
    /// An expanded DNS name exceeds 255 bytes.
    #[error("DNS name exceeds 255 bytes")]
    NameTooLong,
    /// A label contains non-UTF-8 bytes.
    #[error("DNS label is not UTF-8")]
    InvalidLabel,
    /// A compression pointer targets itself or later packet data.
    #[error("DNS compression pointer does not target an earlier offset")]
    ForwardPointer,
    /// A compression pointer targets outside the packet.
    #[error("DNS compression pointer is out of bounds")]
    PointerOutOfBounds,
    /// A name uses a reserved label-length encoding.
    #[error("DNS name uses a reserved label encoding")]
    ReservedLabelEncoding,
    /// A compressed name exceeds the defensive pointer-jump bound.
    #[error("DNS compression pointer chain is too deep")]
    TooManyPointerJumps,
    /// A supported record's RDATA has an invalid shape.
    #[error("invalid DNS record data")]
    InvalidRecordData,
    /// Bytes remain after every declared section has been decoded.
    #[error("DNS packet has undeclared trailing bytes")]
    TrailingBytes,
}

pub(crate) fn names_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

pub(crate) fn encode_query() -> Vec<u8> {
    let message = DnsMessage {
        id: 0,
        flags: 0,
        questions: vec![DnsQuestion {
            name: SERVICE_NAME.to_string(),
            qtype: TYPE_PTR,
            class: CLASS_IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    encode_message(&message).expect("constant query is encodable")
}

#[derive(Clone, Debug)]
pub(crate) struct ResponseSpec {
    pub id: u16,
    pub question: Option<DnsQuestion>,
    pub ptr_owner: String,
    pub ptr_target: String,
    pub txt_values: Vec<Vec<u8>>,
    pub ttl_seconds: u32,
    pub txt_cache_flush: bool,
    pub max_packet_bytes: usize,
}

pub(crate) fn encode_response_segments(spec: ResponseSpec) -> Vec<Vec<u8>> {
    let base = |txt_values: &[Vec<u8>]| DnsMessage {
        id: spec.id,
        flags: FLAG_QR | FLAG_AA,
        questions: spec.question.clone().into_iter().collect(),
        answers: vec![DnsRecord {
            name: spec.ptr_owner.clone(),
            rr_type: TYPE_PTR,
            class: CLASS_IN,
            ttl: spec.ttl_seconds,
            data: DnsRecordData::Ptr(spec.ptr_target.clone()),
        }],
        authorities: Vec::new(),
        additionals: txt_values
            .iter()
            .cloned()
            .map(|value| DnsRecord {
                name: spec.ptr_target.clone(),
                rr_type: TYPE_TXT,
                class: CLASS_IN
                    | if spec.txt_cache_flush {
                        CLASS_HIGH_BIT
                    } else {
                        0
                    },
                ttl: spec.ttl_seconds,
                data: DnsRecordData::Txt(vec![value]),
            })
            .collect(),
    };

    if spec.txt_values.is_empty() {
        return encode_message(&base(&[]))
            .filter(|packet| packet.len() <= spec.max_packet_bytes)
            .into_iter()
            .collect();
    }

    let mut packets = Vec::new();
    let mut current = Vec::new();
    for value in &spec.txt_values {
        if value.len() > u8::MAX as usize {
            continue;
        }
        let mut candidate = current.clone();
        candidate.push(value.clone());
        let encoded = encode_message(&base(&candidate));
        if encoded
            .as_ref()
            .is_some_and(|packet| packet.len() <= spec.max_packet_bytes)
        {
            current = candidate;
            continue;
        }
        if !current.is_empty()
            && let Some(packet) = encode_message(&base(&current))
            && packet.len() <= spec.max_packet_bytes
        {
            packets.push(packet);
        }
        current.clear();
        let one = vec![value.clone()];
        if encode_message(&base(&one))
            .as_ref()
            .is_some_and(|packet| packet.len() <= spec.max_packet_bytes)
        {
            current = one;
        }
    }
    if !current.is_empty()
        && let Some(packet) = encode_message(&base(&current))
        && packet.len() <= spec.max_packet_bytes
    {
        packets.push(packet);
    }
    if packets.is_empty()
        && let Some(packet) = encode_message(&base(&[]))
        && packet.len() <= spec.max_packet_bytes
    {
        packets.push(packet);
    }
    packets
}

fn decode_records(
    packet: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<DnsRecord>, DnsCodecError> {
    let mut records = Vec::with_capacity(count.min(32));
    for _ in 0..count {
        let name = decode_name(packet, cursor)?;
        let rr_type = take_u16(packet, cursor)?;
        let class = take_u16(packet, cursor)?;
        let ttl = take_u32(packet, cursor)?;
        let rdata_len = take_u16(packet, cursor)? as usize;
        let rdata_start = *cursor;
        let rdata_end = rdata_start
            .checked_add(rdata_len)
            .filter(|end| *end <= packet.len())
            .ok_or(DnsCodecError::Truncated)?;
        let data = match rr_type {
            TYPE_PTR => {
                let mut rdata_cursor = rdata_start;
                let name = decode_name(packet, &mut rdata_cursor)?;
                if rdata_cursor != rdata_end {
                    return Err(DnsCodecError::InvalidRecordData);
                }
                Some(DnsRecordData::Ptr(name))
            }
            TYPE_TXT => {
                let mut strings = Vec::new();
                let mut pos = rdata_start;
                while pos < rdata_end {
                    let len = packet[pos] as usize;
                    pos += 1;
                    let end = pos
                        .checked_add(len)
                        .filter(|end| *end <= rdata_end)
                        .ok_or(DnsCodecError::InvalidRecordData)?;
                    strings.push(packet[pos..end].to_vec());
                    pos = end;
                }
                Some(DnsRecordData::Txt(strings))
            }
            _ => None,
        };
        *cursor = rdata_end;
        if let Some(data) = data {
            records.push(DnsRecord {
                name,
                rr_type,
                class,
                ttl,
                data,
            });
        }
    }
    Ok(records)
}

fn decode_name(packet: &[u8], cursor: &mut usize) -> Result<String, DnsCodecError> {
    let mut pos = *cursor;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut encoded_len = 1usize;
    let mut jumps = 0usize;
    loop {
        let first = *packet.get(pos).ok_or(DnsCodecError::Truncated)?;
        match first & 0xc0 {
            0x00 => {
                pos += 1;
                if first == 0 {
                    *cursor = resume.unwrap_or(pos);
                    return Ok(labels.join("."));
                }
                let len = first as usize;
                if len > 63 {
                    return Err(DnsCodecError::LabelTooLong);
                }
                let end = pos
                    .checked_add(len)
                    .filter(|end| *end <= packet.len())
                    .ok_or(DnsCodecError::Truncated)?;
                encoded_len = encoded_len
                    .checked_add(len + 1)
                    .filter(|len| *len <= 255)
                    .ok_or(DnsCodecError::NameTooLong)?;
                let label = core::str::from_utf8(&packet[pos..end])
                    .map_err(|_| DnsCodecError::InvalidLabel)?;
                labels.push(label.to_string());
                pos = end;
            }
            0xc0 => {
                let second = *packet.get(pos + 1).ok_or(DnsCodecError::Truncated)?;
                let target = (usize::from(first & 0x3f) << 8) | usize::from(second);
                if target >= packet.len() {
                    return Err(DnsCodecError::PointerOutOfBounds);
                }
                if target >= pos {
                    return Err(DnsCodecError::ForwardPointer);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsCodecError::TooManyPointerJumps);
                }
                resume.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return Err(DnsCodecError::ReservedLabelEncoding),
        }
    }
}

fn encode_message(message: &DnsMessage) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    write_u16(&mut out, message.id);
    write_u16(&mut out, message.flags);
    write_u16(&mut out, u16::try_from(message.questions.len()).ok()?);
    write_u16(&mut out, u16::try_from(message.answers.len()).ok()?);
    write_u16(&mut out, u16::try_from(message.authorities.len()).ok()?);
    write_u16(&mut out, u16::try_from(message.additionals.len()).ok()?);
    for question in &message.questions {
        write_name(&mut out, &question.name)?;
        write_u16(&mut out, question.qtype);
        write_u16(&mut out, question.class);
    }
    for record in message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
    {
        write_record(&mut out, record)?;
    }
    Some(out)
}

fn write_record(out: &mut Vec<u8>, record: &DnsRecord) -> Option<()> {
    write_name(out, &record.name)?;
    write_u16(out, record.rr_type);
    write_u16(out, record.class);
    write_u32(out, record.ttl);
    let len_pos = out.len();
    write_u16(out, 0);
    let start = out.len();
    match &record.data {
        DnsRecordData::Ptr(name) => write_name(out, name)?,
        DnsRecordData::Txt(strings) => {
            for value in strings {
                out.push(u8::try_from(value.len()).ok()?);
                out.extend_from_slice(value);
            }
        }
    }
    let len = u16::try_from(out.len().checked_sub(start)?).ok()?;
    out[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes());
    Some(())
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    let start = out.len();
    if name.is_empty() {
        out.push(0);
        return Some(());
    }
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    (out.len().checked_sub(start)? <= 255).then_some(())
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsCodecError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(DnsCodecError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take_u16(packet: &[u8], cursor: &mut usize) -> Result<u16, DnsCodecError> {
    let value = read_u16(packet, *cursor)?;
    *cursor += 2;
    Ok(value)
}

fn take_u32(packet: &[u8], cursor: &mut usize) -> Result<u32, DnsCodecError> {
    let bytes = packet
        .get(*cursor..*cursor + 4)
        .ok_or(DnsCodecError::Truncated)?;
    *cursor += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_query_is_33_bytes_with_zero_id() {
        let query = encode_query();
        assert_eq!(
            query,
            [
                0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, b'_', b'p', b'2', b'p', 4, b'_', b'u', b'd',
                b'p', 5, b'l', b'o', b'c', b'a', b'l', 0, 0, 12, 0, 1,
            ]
        );
        let decoded = DnsMessage::decode(&query).unwrap();
        assert!(!decoded.is_response());
        assert_eq!(decoded.questions[0].name, SERVICE_NAME);
    }

    #[test]
    fn decreasing_pointer_to_pointer_chain_is_accepted() {
        let mut packet = encode_query();
        packet[4..6].copy_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c, 0, TYPE_PTR as u8, 0, 1]);
        let second_offset = packet.len();
        packet.extend_from_slice(&[0xc0, 0x21, 0, TYPE_PTR as u8, 0, 1]);
        assert!(second_offset > 0x21);
        let decoded = DnsMessage::decode(&packet).unwrap();
        assert_eq!(decoded.questions[2].name, SERVICE_NAME);
    }

    #[test]
    fn pointer_to_name_starting_inside_prior_ptr_rdata_is_accepted() {
        let target = "peer._p2p._udp.local";
        let mut packet = encode_response_segments(ResponseSpec {
            id: 0,
            question: None,
            ptr_owner: SERVICE_NAME.to_string(),
            ptr_target: target.to_string(),
            txt_values: Vec::new(),
            ttl_seconds: 120,
            txt_cache_flush: true,
            max_packet_bytes: 1_400,
        })
        .remove(0);
        let mut target_wire = Vec::new();
        write_name(&mut target_wire, target).unwrap();
        let target_offset = packet
            .windows(target_wire.len())
            .position(|window| window == target_wire)
            .expect("PTR RDATA target is present");
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        let pointer = 0xc000 | u16::try_from(target_offset).unwrap();
        packet.extend_from_slice(&pointer.to_be_bytes());
        packet.extend_from_slice(&TYPE_TXT.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet.extend_from_slice(&120u32.to_be_bytes());
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&[1, b'x']);

        let decoded = DnsMessage::decode(&packet).unwrap();
        assert_eq!(decoded.additionals[0].name, target);
    }

    #[test]
    fn forward_reserved_and_out_of_bounds_pointers_fail() {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1]);
        assert_eq!(
            DnsMessage::decode(&packet),
            Err(DnsCodecError::ForwardPointer)
        );
        packet[12] = 0x40;
        assert_eq!(
            DnsMessage::decode(&packet),
            Err(DnsCodecError::ReservedLabelEncoding)
        );
        packet[12] = 0xc0;
        packet[13] = 0x7f;
        assert_eq!(
            DnsMessage::decode(&packet),
            Err(DnsCodecError::PointerOutOfBounds)
        );
    }

    #[test]
    fn response_segments_repeat_ptr_and_obey_size_limit() {
        let values = (0..8)
            .map(|index| {
                let mut value = b"dnsaddr=/dns/".to_vec();
                value.extend(core::iter::repeat_n(b'a' + index, 180));
                value
            })
            .collect();
        let packets = encode_response_segments(ResponseSpec {
            id: 0,
            question: None,
            ptr_owner: SERVICE_NAME.to_string(),
            ptr_target: "fixed._p2p._udp.local".to_string(),
            txt_values: values,
            ttl_seconds: 120,
            txt_cache_flush: true,
            max_packet_bytes: 512,
        });
        assert!(packets.len() > 1);
        for packet in packets {
            assert!(packet.len() <= 512);
            let decoded = DnsMessage::decode(&packet).unwrap();
            assert_eq!(decoded.answers.len(), 1);
            assert!(matches!(decoded.answers[0].data, DnsRecordData::Ptr(_)));
            assert_eq!(decoded.answers[0].class, 0x0001);
            assert!(
                decoded
                    .additionals
                    .iter()
                    .all(|record| record.class == 0x8001)
            );
        }
    }

    #[test]
    fn unknown_records_are_skipped_in_every_section() {
        let mut packet = vec![0; 12];
        packet[7] = 1;
        packet.extend_from_slice(&[0, 0, 99, 0, 1, 0, 0, 0, 1, 0, 2, 1, 2]);
        let decoded = DnsMessage::decode(&packet).unwrap();
        assert!(decoded.answers.is_empty());
    }

    #[test]
    fn packet_cap_is_strict() {
        assert_eq!(
            DnsMessage::decode(&vec![0; MDNS_MAX_DECODE_BYTES + 1]),
            Err(DnsCodecError::PacketTooLarge)
        );
    }
}
