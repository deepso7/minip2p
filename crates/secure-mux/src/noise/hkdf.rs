use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of every length.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub(crate) fn derive2(chaining_key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = hmac(chaining_key, &[input]);
    let output1 = hmac(&temp_key, &[&[1]]);
    let output2 = hmac(&temp_key, &[&output1, &[2]]);
    (output1, output2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_and_domain_separated() {
        let (a, b) = derive2(&[7; 32], b"input");
        assert_eq!((a, b), derive2(&[7; 32], b"input"));
        assert_ne!(a, b);
    }
}
