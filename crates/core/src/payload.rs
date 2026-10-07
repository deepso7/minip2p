//! The retained-slice rule for stream payloads (ADR 0012).

use bytes::Bytes;

/// Bounds the memory a kept slice of a payload can pin.
///
/// `counted` is the length the slice's allocation was counted at -- the
/// payload's original length the first time. Once `slice` is shorter than
/// half of it, the slice moves to its own buffer and `counted` becomes its
/// length, so a layer that keeps a tail retains at most twice the bytes it
/// counts. Call it whenever a kept slice shrinks.
pub fn retain_slice(slice: &mut Bytes, counted: &mut usize) {
    if slice.len().saturating_mul(2) < *counted {
        *slice = Bytes::copy_from_slice(slice);
        *counted = slice.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_tail_is_copied_and_a_long_one_stays_a_slice() {
        let payload = Bytes::from(alloc::vec![7u8; 100]);

        let mut long = payload.slice(40..);
        let mut counted = payload.len();
        retain_slice(&mut long, &mut counted);
        assert_eq!(long.as_ptr(), payload.as_ptr().wrapping_add(40));
        assert_eq!(counted, 100);

        let mut short = payload.slice(90..);
        retain_slice(&mut short, &mut counted);
        assert_ne!(short.as_ptr(), payload.as_ptr().wrapping_add(90));
        assert_eq!((short.as_ref(), counted), (&[7u8; 10][..], 10));
    }
}
