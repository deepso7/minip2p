//! QPACK (RFC 9204) restricted to the static table.
//!
//! Our side advertises `QPACK_MAX_TABLE_CAPACITY = 0` and
//! `QPACK_BLOCKED_STREAMS = 0` (the defaults), so a conforming peer never
//! references the dynamic table. [`QpackDecoder`] therefore accepts only
//! field sections with Required Insert Count 0, built from indexed static
//! entries and literals (Huffman-coded or not), and rejects everything else
//! with [`Error::QpackDecompressionFailed`]. [`encode_field_section`] emits
//! the same subset without Huffman, and [`DecoderStreamReader`] checks that
//! the peer's decoder stream acknowledges nothing it was never sent.
//!
//! ```
//! use minip2p_webtransport::qpack::{QpackDecoder, encode_field_section};
//!
//! let mut block = Vec::new();
//! encode_field_section([(&b":status"[..], &b"200"[..])], &mut block);
//! assert_eq!(block, [0x00, 0x00, 0xd9]);
//!
//! let mut decoder = QpackDecoder::new();
//! let section = decoder.decode(&block)?;
//! assert_eq!(section.get(b":status"), Some(&b"200"[..]));
//! # Ok::<(), minip2p_webtransport::Error>(())
//! ```

mod huffman;
mod static_table;

use alloc::vec::Vec;

use crate::Error;
use static_table::STATIC_TABLE;

/// The decoded field section cap, counted the RFC 9114 §4.2.2 way: each
/// field costs `name.len() + value.len() + 32`.
pub const MAX_FIELD_SECTION_SIZE: usize = 8 * 1024;
/// The most field lines one section may hold.
pub const MAX_FIELDS: usize = 64;
/// The per-field overhead in the size accounting.
const FIELD_OVERHEAD: usize = 32;

/// One decoded field line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Field<'a> {
    /// The field name.
    pub name: &'a [u8],
    /// The field value.
    pub value: &'a [u8],
}

/// A decoded field section, borrowed from its [`QpackDecoder`].
#[derive(Clone, Copy, Debug)]
pub struct FieldSection<'a> {
    buf: &'a [u8],
    spans: &'a [Span],
}

#[derive(Clone, Copy, Debug)]
struct Span {
    start: usize,
    name_len: usize,
    end: usize,
}

impl<'a> FieldSection<'a> {
    /// The fields in wire order.
    pub fn iter(&self) -> impl Iterator<Item = Field<'a>> + 'a {
        let buf = self.buf;
        self.spans.iter().map(move |span| {
            let field = buf.get(span.start..span.end).unwrap_or_default();
            let (name, value) = field.split_at(span.name_len.min(field.len()));
            Field { name, value }
        })
    }

    /// The value of the first field called `name`.
    pub fn get(&self, name: &[u8]) -> Option<&'a [u8]> {
        self.iter()
            .find(|field| field.name == name)
            .map(|field| field.value)
    }

    /// The number of fields.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    /// Whether the section has no fields.
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

/// A static-table QPACK decoder that writes every field into one
/// preallocated [`MAX_FIELD_SECTION_SIZE`] buffer, reused across sections.
#[derive(Clone, Debug)]
pub struct QpackDecoder {
    buf: Vec<u8>,
    spans: Vec<Span>,
}

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackDecoder {
    /// A decoder with its buffers allocated up front.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(MAX_FIELD_SECTION_SIZE),
            spans: Vec::with_capacity(MAX_FIELDS),
        }
    }

    /// Decodes one encoded field section (a HEADERS frame payload).
    ///
    /// Fails with [`Error::QpackDecompressionFailed`] on a malformed block,
    /// any dynamic-table reference, more than [`MAX_FIELDS`] fields, or a
    /// decoded size past [`MAX_FIELD_SECTION_SIZE`], however few encoded
    /// bytes produced it.
    pub fn decode(&mut self, mut block: &[u8]) -> Result<FieldSection<'_>, Error> {
        self.buf.clear();
        self.spans.clear();
        let input = &mut block;
        // Required Insert Count must be 0; the Base is then unused, but a
        // sign bit would make it 0 - Delta Base - 1, which is negative
        // (RFC 9204 §4.5.1.2).
        if decode_int(input, 8)? != 0 || input.first().is_some_and(|&byte| byte & 0x80 != 0) {
            return Err(Error::QpackDecompressionFailed);
        }
        decode_int(input, 7)?;
        let mut size = 0usize;
        while let Some(&first) = input.first() {
            if self.spans.len() == MAX_FIELDS {
                return Err(Error::QpackDecompressionFailed);
            }
            size += FIELD_OVERHEAD;
            if size > MAX_FIELD_SECTION_SIZE {
                return Err(Error::QpackDecompressionFailed);
            }
            // Name and value bytes may fill what the accounting has left.
            let limit = self.buf.len() + (MAX_FIELD_SECTION_SIZE - size);
            let start = self.buf.len();
            let name_len = if first & 0x80 != 0 {
                // Indexed field line: 1 T index(6).
                let (name, value) = static_entry(first & 0x40, decode_int(input, 6)?)?;
                push(&mut self.buf, name, limit)?;
                push(&mut self.buf, value, limit)?;
                name.len()
            } else if first & 0x40 != 0 {
                // Literal with name reference: 0 1 N T index(4), value.
                let (name, _) = static_entry(first & 0x10, decode_int(input, 4)?)?;
                push(&mut self.buf, name, limit)?;
                decode_string(input, 7, &mut self.buf, limit)?;
                name.len()
            } else if first & 0x20 != 0 {
                // Literal with literal name: 0 0 1 N H len(3), name, value.
                decode_string(input, 3, &mut self.buf, limit)?;
                let name_len = self.buf.len() - start;
                decode_string(input, 7, &mut self.buf, limit)?;
                name_len
            } else {
                // Post-base indexed or post-base name reference: dynamic.
                return Err(Error::QpackDecompressionFailed);
            };
            size += self.buf.len() - start;
            self.spans.push(Span {
                start,
                name_len,
                end: self.buf.len(),
            });
        }
        Ok(FieldSection {
            buf: &self.buf,
            spans: &self.spans,
        })
    }
}

/// Validates the peer's QPACK decoder stream (RFC 9204 §4.4) for an encoder
/// that only ever uses the static table.
///
/// Feed it every byte after the stream type, in order. Stream Cancellation
/// is always legal. A Section Acknowledgment or Insert Count Increment
/// (including an increment of 0) refers to dynamic-table state that does
/// not exist, so each is [`Error::QpackDecoderStream`], fatal to the
/// connection.
#[derive(Clone, Debug, Default)]
pub struct DecoderStreamReader {
    /// The shift of the next continuation byte of a Stream Cancellation's
    /// stream id, while one is being read.
    continuation: Option<u32>,
}

impl DecoderStreamReader {
    /// A reader at the start of the stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks the next bytes of the stream.
    pub fn read(&mut self, input: &[u8]) -> Result<(), Error> {
        for &byte in input {
            self.continuation = match self.continuation {
                // A stream id needs no more than 2^62, as in `decode_int`.
                Some(shift) if shift > 56 => return Err(Error::QpackDecoderStream),
                Some(shift) => (byte & 0x80 != 0).then_some(shift + 7),
                // Stream Cancellation: 0 1 stream id(6).
                None if byte & 0xc0 == 0x40 => (byte & 0x3f == 0x3f).then_some(0),
                None => return Err(Error::QpackDecoderStream),
            };
        }
        Ok(())
    }

    /// Whether the stream sits between instructions.
    pub fn is_at_instruction_boundary(&self) -> bool {
        self.continuation.is_none()
    }
}

/// Looks up a static entry; a clear `static_bit` means the dynamic table.
fn static_entry(static_bit: u8, index: u64) -> Result<(&'static [u8], &'static [u8]), Error> {
    if static_bit == 0 {
        return Err(Error::QpackDecompressionFailed);
    }
    usize::try_from(index)
        .ok()
        .and_then(|index| STATIC_TABLE.get(index))
        .copied()
        .ok_or(Error::QpackDecompressionFailed)
}

fn push(buf: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), Error> {
    if buf.len() + bytes.len() > limit {
        return Err(Error::QpackDecompressionFailed);
    }
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Reads a string literal whose Huffman flag sits just above an
/// `prefix_bits`-bit length prefix.
fn decode_string(
    input: &mut &[u8],
    prefix_bits: u8,
    buf: &mut Vec<u8>,
    limit: usize,
) -> Result<(), Error> {
    let huffman = input.first().ok_or(Error::QpackDecompressionFailed)? & (1 << prefix_bits) != 0;
    let len = usize::try_from(decode_int(input, prefix_bits)?)
        .ok()
        .ok_or(Error::QpackDecompressionFailed)?;
    if len > input.len() {
        return Err(Error::QpackDecompressionFailed);
    }
    let (bytes, rest) = input.split_at(len);
    *input = rest;
    if huffman {
        huffman::decode(bytes, buf, limit)
    } else {
        push(buf, bytes, limit)
    }
}

/// Decodes an RFC 7541 §5.1 prefix integer from the low `prefix_bits` of the
/// first byte. Values past 2^62 are rejected as malformed.
fn decode_int(input: &mut &[u8], prefix_bits: u8) -> Result<u64, Error> {
    let (&first, rest) = input.split_first().ok_or(Error::QpackDecompressionFailed)?;
    *input = rest;
    let mask = u8::MAX >> (8 - prefix_bits);
    let mut value = u64::from(first & mask);
    if value < u64::from(mask) {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let (&byte, rest) = input.split_first().ok_or(Error::QpackDecompressionFailed)?;
        *input = rest;
        if shift > 56 {
            return Err(Error::QpackDecompressionFailed);
        }
        value += u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Appends a prefix integer: `flags` fill the bits above the low
/// `prefix_bits` of the first byte.
fn encode_int(out: &mut Vec<u8>, flags: u8, prefix_bits: u8, mut value: u64) {
    let mask = u8::MAX >> (8 - prefix_bits);
    if value < u64::from(mask) {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | mask);
    value -= u64::from(mask);
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Appends an encoded field section for `fields` to `out` (the payload of a
/// HEADERS frame). Exact static-table matches become indexed lines, static
/// names become name references, and everything else a literal; no string is
/// Huffman-coded and the dynamic table is never used.
pub fn encode_field_section<'a>(
    fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    out: &mut Vec<u8>,
) {
    // Required Insert Count 0, Base 0.
    out.extend_from_slice(&[0x00, 0x00]);
    for (name, value) in fields {
        if let Some(index) = STATIC_TABLE
            .iter()
            .position(|&entry| entry == (name, value))
        {
            encode_int(out, 0xc0, 6, index as u64);
            continue;
        }
        match STATIC_TABLE.iter().position(|&(entry, _)| entry == name) {
            Some(index) => encode_int(out, 0x50, 4, index as u64),
            None => {
                encode_int(out, 0x20, 3, name.len() as u64);
                out.extend_from_slice(name);
            }
        }
        encode_int(out, 0x00, 7, value.len() as u64);
        out.extend_from_slice(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn fields(section: &FieldSection<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
        section
            .iter()
            .map(|field| (field.name.to_vec(), field.value.to_vec()))
            .collect()
    }

    fn pair(name: &str, value: &str) -> (Vec<u8>, Vec<u8>) {
        (name.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    #[test]
    fn prefix_integers_match_rfc_7541_c1() {
        let cases: [(&[u8], u8, u64); 3] = [
            (&[0x0a], 5, 10),
            (&[0x1f, 0x9a, 0x0a], 5, 1337),
            (&[0x2a], 8, 42),
        ];
        for (bytes, prefix_bits, value) in cases {
            let mut input = bytes;
            assert_eq!(decode_int(&mut input, prefix_bits), Ok(value));
            let mut out = Vec::new();
            encode_int(&mut out, 0, prefix_bits, value);
            assert_eq!(out, bytes);
        }
        let mut overflow: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        ];
        assert_eq!(
            decode_int(&mut overflow, 8),
            Err(Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn decodes_rfc_9204_b1_and_encodes_it_back() {
        let block = [
            0x00, 0x00, 0x51, 0x0b, 0x2f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x2e, 0x68, 0x74, 0x6d,
            0x6c,
        ];
        let mut decoder = QpackDecoder::new();
        let section = decoder.decode(&block).unwrap();
        assert_eq!(fields(&section), [pair(":path", "/index.html")]);
        let mut out = Vec::new();
        encode_field_section([(&b":path"[..], &b"/index.html"[..])], &mut out);
        assert_eq!(out, block);
    }

    #[test]
    fn decodes_a_huffman_value_from_rfc_7541_c4() {
        // :authority (static 0) with "www.example.com" Huffman-coded.
        let block = [
            0x00, 0x00, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
            0xf4, 0xff,
        ];
        let mut decoder = QpackDecoder::new();
        let section = decoder.decode(&block).unwrap();
        assert_eq!(section.get(b":authority"), Some(&b"www.example.com"[..]));
        // A literal name, Huffman-coded ("custom-key"), with a Huffman value.
        let block = [
            0x00, 0x00, 0x2f, 0x01, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25,
            0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf,
        ];
        let section = decoder.decode(&block).unwrap();
        assert_eq!(fields(&section), [pair("custom-key", "custom-value")]);
    }

    #[test]
    fn dynamic_table_references_are_rejected() {
        let cases: [&[u8]; 5] = [
            &[0x03, 0x81, 0x10], // RFC 9204 B.2: Required Insert Count 2, post-base index
            &[0x00, 0x00, 0x80], // indexed, dynamic
            &[0x00, 0x00, 0x40, 0x00], // name reference, dynamic
            &[0x00, 0x00, 0x10], // post-base indexed
            &[0x00, 0x00, 0x00, 0x00], // post-base name reference
        ];
        let mut decoder = QpackDecoder::new();
        for block in cases {
            assert_eq!(
                decoder.decode(block).err(),
                Some(Error::QpackDecompressionFailed),
                "{block:02x?}"
            );
        }
    }

    #[test]
    fn a_negative_base_is_rejected_and_an_unused_positive_one_accepted() {
        let mut decoder = QpackDecoder::new();
        // Required Insert Count 0 with the Delta Base sign set: Base -1.
        for block in [&[0x00, 0x80, 0xd9][..], &[0x00, 0x85, 0xd9]] {
            assert_eq!(
                decoder.decode(block).err(),
                Some(Error::QpackDecompressionFailed),
                "{block:02x?}"
            );
        }
        let section = decoder.decode(&[0x00, 0x05, 0xd9]).unwrap();
        assert_eq!(section.get(b":status"), Some(&b"200"[..]));
    }

    #[test]
    fn decoder_streams_carry_only_stream_cancellations() {
        // Stream Cancellation of streams 4 and 1000 (a continued integer),
        // split byte by byte.
        let mut stream = DecoderStreamReader::new();
        for byte in [0x44, 0x7f, 0xa9, 0x0f] {
            assert_eq!(stream.read(&[byte]), Ok(()));
        }
        assert!(stream.is_at_instruction_boundary());
        // An Insert Count Increment of 0 or 1, and a Section Acknowledgment,
        // all refer to a dynamic table this encoder never uses.
        for bytes in [&[0x00][..], &[0x01], &[0x84], &[0x44, 0x01]] {
            assert_eq!(
                DecoderStreamReader::new().read(bytes),
                Err(Error::QpackDecoderStream),
                "{bytes:02x?}"
            );
        }
        // A cancellation whose integer runs past 2^62.
        let mut overflow = vec![0x7f];
        overflow.resize(12, 0xff);
        assert_eq!(
            DecoderStreamReader::new().read(&overflow),
            Err(Error::QpackDecoderStream)
        );
    }

    #[test]
    fn malformed_blocks_are_rejected() {
        let cases: [&[u8]; 4] = [
            &[],                             // no prefix
            &[0x00, 0x00, 0xff],             // static index past the table, truncated int
            &[0x00, 0x00, 0xff, 0x24],       // static index 99
            &[0x00, 0x00, 0x51, 0x05, b'/'], // value shorter than its length
        ];
        let mut decoder = QpackDecoder::new();
        for block in cases {
            assert_eq!(
                decoder.decode(block).err(),
                Some(Error::QpackDecompressionFailed),
                "{block:02x?}"
            );
        }
    }

    #[test]
    fn a_2_kib_headers_frame_expanding_past_8_kib_hits_the_size_cap() {
        use crate::h3::{Frame, FrameDecoder, encode_frame, frame_type};
        // 63 references to the static content-security-policy (108 bytes
        // each as counted) and a `:path` whose Huffman value of `huffman`
        // zero bytes expands to 8/5 as many characters: 64 fields, within
        // the field cap whatever the size.
        fn headers(huffman: usize) -> Vec<u8> {
            let csp = STATIC_TABLE
                .iter()
                .position(|(name, _)| *name == b"content-security-policy")
                .unwrap();
            let mut block = vec![0x00, 0x00];
            for _ in 0..63 {
                encode_int(&mut block, 0xc0, 6, csp as u64);
            }
            block.push(0x51);
            encode_int(&mut block, 0x80, 7, huffman as u64);
            block.resize(block.len() + huffman, 0x00);
            let mut frame = Vec::new();
            encode_frame(frame_type::HEADERS, &block, &mut frame).unwrap();
            frame
        }
        // The field section a HEADERS frame carries.
        fn block(frame: &[u8]) -> Vec<u8> {
            let mut input = frame;
            let Ok(Some(Frame::Headers(block))) = FrameDecoder::new().decode(&mut input) else {
                panic!("not a HEADERS frame");
            };
            block
        }
        let mut decoder = QpackDecoder::new();
        // 6804 + 837 bytes decoded: under 8 KiB.
        let fields = decoder.decode(&block(&headers(500))).map(|s| s.len());
        assert_eq!(fields, Ok(64));
        // 6804 + 3077 bytes decoded from a frame under 2 KiB.
        let frame = headers(1900);
        assert!(frame.len() <= 2 * 1024, "{}", frame.len());
        assert_eq!(
            decoder.decode(&block(&frame)).err(),
            Some(Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn sixty_five_fields_are_rejected_and_sixty_four_accepted() {
        let mut block = vec![0x00, 0x00];
        block.resize(2 + 64, 0xd9);
        let mut decoder = QpackDecoder::new();
        assert_eq!(decoder.decode(&block).map(|section| section.len()), Ok(64));
        block.push(0xd9);
        assert_eq!(
            decoder.decode(&block).err(),
            Some(Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn decoded_size_is_capped_however_small_the_encoding() {
        // Each value is 2045 bytes of Huffman `0` codes (5 bits each), which
        // expand to 3272 bytes: three such fields pass 8 KiB.
        fn huffman_zeros(block: &mut Vec<u8>) {
            // `:path` name reference, Huffman value of 2045 bytes.
            block.push(0x51);
            encode_int(block, 0x80, 7, 2045);
            block.resize(block.len() + 2045, 0x00);
        }
        let mut block = vec![0x00, 0x00];
        huffman_zeros(&mut block);
        huffman_zeros(&mut block);
        let mut decoder = QpackDecoder::new();
        let section = decoder.decode(&block).unwrap();
        assert_eq!(section.get(b":path").map(<[u8]>::len), Some(3272));
        huffman_zeros(&mut block);
        assert_eq!(
            decoder.decode(&block).err(),
            Some(Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn the_size_cap_counts_32_bytes_per_field() {
        // One literal-name field whose name + value + 32 is exactly 8 KiB.
        let value = vec![b'v'; MAX_FIELD_SECTION_SIZE - 32 - 1];
        let mut block = Vec::new();
        encode_field_section([(&b"x"[..], value.as_slice())], &mut block);
        let mut decoder = QpackDecoder::new();
        assert_eq!(decoder.decode(&block).map(|section| section.len()), Ok(1));
        let value = vec![b'v'; MAX_FIELD_SECTION_SIZE - 32];
        block.clear();
        encode_field_section([(&b"x"[..], value.as_slice())], &mut block);
        assert_eq!(
            decoder.decode(&block).err(),
            Some(Error::QpackDecompressionFailed)
        );
    }

    #[test]
    fn encoder_output_round_trips_a_connect_request() {
        let request: [(&[u8], &[u8]); 6] = [
            (b":method", b"CONNECT"),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", b"127.0.0.1:4433"),
            (b":path", b"/.well-known/libp2p-webtransport?type=noise"),
            (b"sec-webtransport-http3-draft02", b"1"),
        ];
        let mut block = Vec::new();
        encode_field_section(request, &mut block);
        // `:method CONNECT` and `:scheme https` are indexed static entries.
        assert_eq!(block.get(..3), Some(&[0x00, 0x00, 0xcf][..]));
        let mut decoder = QpackDecoder::new();
        let section = decoder.decode(&block).unwrap();
        let decoded: Vec<_> = section
            .iter()
            .map(|field| (field.name, field.value))
            .collect();
        assert_eq!(decoded, request);
    }

    #[test]
    fn status_200_encodes_to_three_bytes() {
        let mut out = Vec::new();
        encode_field_section([(&b":status"[..], &b"200"[..])], &mut out);
        assert_eq!(out, [0x00, 0x00, 0xd9]);
    }
}
