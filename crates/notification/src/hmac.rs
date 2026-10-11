//! HMAC-SHA-256 (RFC 2104) over `sha2`, for signing webhook bodies
//! (ADR 0045). Small enough to own; tested against RFC 4231.

use sha2::{Digest, Sha256};

const BLOCK: usize = 64;

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner_pad: Vec<u8> = block.iter().map(|b| b ^ 0x36).collect();
    let outer_pad: Vec<u8> = block.iter().map(|b| b ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(&outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `X-WNM-Signature` value for a body sent at `timestamp` (Unix
/// seconds): `sha256=` and the hex HMAC of `"{timestamp}.{body}"`. Binding
/// the time stops a captured request being replayed later.
pub fn signature(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut message = format!("{timestamp}.").into_bytes();
    message.extend_from_slice(body);
    format!("sha256={}", hex(&hmac_sha256(secret, &message)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231, test cases 1, 2 and 6.
    #[test]
    fn rfc_4231_vectors() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn the_signature_binds_the_time() {
        let a = signature(b"secret", 1_800_000_000, b"{}");
        assert!(a.starts_with("sha256=") && a.len() == 7 + 64);
        assert_ne!(a, signature(b"secret", 1_800_000_001, b"{}"));
        assert_ne!(a, signature(b"other", 1_800_000_000, b"{}"));
    }
}
