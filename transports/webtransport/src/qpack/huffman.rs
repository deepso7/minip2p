//! RFC 7541 Appendix B Huffman decoding (QPACK reuses the HPACK code).

use alloc::vec::Vec;

use crate::Error;

/// The longest code, in bits (EOS).
const MAX_LEN: usize = 30;
/// The end-of-string symbol, which must never appear inside a string.
const EOS: u16 = 256;

/// Canonical decoding tables derived from the code lengths: the code is
/// canonical by (length, symbol), so per length the codes form one
/// contiguous range starting at `first`.
struct Tables {
    count: [u32; MAX_LEN + 1],
    first: [u32; MAX_LEN + 1],
    offset: [usize; MAX_LEN + 1],
    symbols: [u16; 257],
}

const TABLES: Tables = build();

#[expect(
    clippy::indexing_slicing,
    reason = "const evaluation: an out-of-bounds index fails the build"
)]
const fn build() -> Tables {
    let mut count = [0u32; MAX_LEN + 1];
    let mut sym = 0;
    while sym < 257 {
        count[HUFFMAN_CODES[sym].1 as usize] += 1;
        sym += 1;
    }
    let mut first = [0u32; MAX_LEN + 1];
    let mut offset = [0usize; MAX_LEN + 1];
    let mut symbols = [0u16; 257];
    let mut code = 0u32;
    let mut next = 0usize;
    let mut len = 1;
    while len <= MAX_LEN {
        code = (code + count[len - 1]) << 1;
        first[len] = code;
        offset[len] = next;
        let mut sym = 0;
        while sym < 257 {
            if HUFFMAN_CODES[sym].1 as usize == len {
                symbols[next] = sym as u16;
                next += 1;
            }
            sym += 1;
        }
        len += 1;
    }
    Tables {
        count,
        first,
        offset,
        symbols,
    }
}

/// Decodes the Huffman string `input`, appending to `out` but never past
/// `limit` total bytes. Overrunning the limit, an EOS symbol, or padding
/// that is longer than 7 bits or not all ones is
/// [`Error::QpackDecompressionFailed`].
pub(crate) fn decode(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let mut code = 0u32;
    let mut len = 0usize;
    for byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            len += 1;
            let (Some(&first), Some(&count), Some(&offset)) = (
                TABLES.first.get(len),
                TABLES.count.get(len),
                TABLES.offset.get(len),
            ) else {
                return Err(Error::QpackDecompressionFailed);
            };
            if code < first || code - first >= count {
                continue;
            }
            let index = offset + (code - first) as usize;
            let symbol = *TABLES
                .symbols
                .get(index)
                .ok_or(Error::QpackDecompressionFailed)?;
            if symbol == EOS || out.len() >= limit {
                return Err(Error::QpackDecompressionFailed);
            }
            out.push(symbol as u8);
            code = 0;
            len = 0;
        }
    }
    // RFC 7541 §5.2: padding is a prefix of EOS (all ones), at most 7 bits.
    if len > 7 || code != (1 << len) - 1 {
        return Err(Error::QpackDecompressionFailed);
    }
    Ok(())
}

// RFC 7541 Appendix B: (code aligned to the LSB, bit length) per symbol, EOS last.
pub(crate) const HUFFMAN_CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(hex: &str) -> Result<Vec<u8>, Error> {
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut out = Vec::new();
        decode(&bytes, &mut out, usize::MAX)?;
        Ok(out)
    }

    #[test]
    fn canonical_tables_reproduce_the_rfc_codes() {
        for (sym, &(code, len)) in HUFFMAN_CODES.iter().enumerate() {
            let len = usize::from(len);
            let index = TABLES.offset[len] + (code - TABLES.first[len]) as usize;
            assert_eq!(usize::from(TABLES.symbols[index]), sym);
        }
    }

    #[test]
    fn decodes_rfc_7541_appendix_c_strings() {
        let vectors: [(&str, &[u8]); 9] = [
            ("f1e3c2e5f23a6ba0ab90f4ff", b"www.example.com"),
            ("a8eb10649cbf", b"no-cache"),
            ("25a849e95ba97d7f", b"custom-key"),
            ("25a849e95bb8e8b4bf", b"custom-value"),
            ("6402", b"302"),
            ("aec3771a4b", b"private"),
            (
                "d07abe941054d444a8200595040b8166e082a62d1bff",
                b"Mon, 21 Oct 2013 20:13:21 GMT",
            ),
            (
                "9d29ad171863c78f0b97c8e9ae82ae43d3",
                b"https://www.example.com",
            ),
            (
                "94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
                b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
            ),
        ];
        for (hex, expected) in vectors {
            assert_eq!(decoded(hex).unwrap(), expected, "{hex}");
        }
    }

    #[test]
    fn rejects_eos_bad_padding_and_overruns() {
        // The 30-bit EOS code, padded with ones.
        assert_eq!(decoded("ffffffff"), Err(Error::QpackDecompressionFailed));
        // "0" (00000) padded with zeros instead of ones.
        assert_eq!(decoded("00"), Err(Error::QpackDecompressionFailed));
        // A whole byte of padding.
        assert_eq!(decoded("6402ff"), Err(Error::QpackDecompressionFailed));
        let mut out = Vec::new();
        assert_eq!(
            decode(&[0x64, 0x02], &mut out, 2),
            Err(Error::QpackDecompressionFailed)
        );
    }
}
