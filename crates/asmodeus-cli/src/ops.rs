//! Offline operator crypto: keygen, sign, verify and scope validation. Pure
//! functions over bytes/strings so they unit-test without files or network.
//! The signing key belongs to the Red Team Lead — this is the operator's tool.

use asmodeus_dsl::path_in_scope;
use ed25519_compact::{KeyPair, SecretKey, Signature};

#[derive(Debug, PartialEq, Eq)]
pub enum OpError {
    BadHex,
    BadKey,
    BadSignature,
    VerifyFailed,
}

impl std::fmt::Display for OpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OpError::BadHex => "malformed hex input",
            OpError::BadKey => "malformed key",
            OpError::BadSignature => "malformed signature",
            OpError::VerifyFailed => "signature does not verify",
        };
        f.write_str(s)
    }
}
impl std::error::Error for OpError {}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn from_hex(s: &str) -> Result<Vec<u8>, OpError> {
    // Work on bytes: slicing a str by byte index would panic on multibyte
    // (non-ASCII) input. A hex digit is a single ASCII byte, so bytes are correct.
    let bytes = s.trim().as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(OpError::BadHex);
    }
    let nibble = |b: u8| -> Result<u8, OpError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(OpError::BadHex),
        }
    };
    bytes
        .chunks_exact(2)
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

/// Generate a fresh Ed25519 keypair. Returns (secret_hex, public_hex).
pub fn generate_keypair() -> (String, String) {
    let kp = KeyPair::generate();
    (to_hex(kp.sk.as_ref()), to_hex(kp.pk.as_ref()))
}

/// Sign a manifest with a secret key (hex). Returns the signature as hex.
pub fn sign(manifest: &[u8], secret_hex: &str) -> Result<String, OpError> {
    let sk_bytes = from_hex(secret_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes).map_err(|_| OpError::BadKey)?;
    Ok(to_hex(sk.sign(manifest, None).as_ref()))
}

/// Verify a manifest signature (hex) against a public key (hex).
pub fn verify(manifest: &[u8], signature_hex: &str, public_hex: &str) -> Result<(), OpError> {
    let sig = from_hex(signature_hex)?;
    let pk = from_hex(public_hex)?;
    // Validate lengths early for clearer errors.
    Signature::from_slice(&sig).map_err(|_| OpError::BadSignature)?;
    if asmodeus_crypto::is_valid(manifest, &sig, &pk) {
        Ok(())
    } else {
        Err(OpError::VerifyFailed)
    }
}

/// INV-0 scope check for a target directory.
pub fn validate_scope(target_dir: &str) -> bool {
    path_in_scope(target_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let bytes = [0x00, 0xa5, 0xff, 0x10];
        assert_eq!(from_hex(&to_hex(&bytes)).unwrap(), bytes);
        assert_eq!(from_hex("00a5ff10").unwrap(), bytes);
        assert!(from_hex("xyz").is_err());
        assert!(from_hex("abc").is_err()); // odd length
    }

    #[test]
    fn from_hex_rejects_non_ascii_without_panic() {
        // Multibyte UTF-8 input must return BadHex, never panic on a str slice.
        assert_eq!(from_hex("aéa"), Err(OpError::BadHex));
        assert_eq!(from_hex("éé"), Err(OpError::BadHex));
        assert_eq!(from_hex("00é0"), Err(OpError::BadHex));
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, pk) = generate_keypair();
        let manifest = b"kind: AttackScenario\nid: SCN-RT-001\n";
        let sig = sign(manifest, &sk).unwrap();
        assert!(verify(manifest, &sig, &pk).is_ok());
    }

    #[test]
    fn tampered_manifest_fails_verify() {
        let (sk, pk) = generate_keypair();
        let sig = sign(b"original", &sk).unwrap();
        assert_eq!(verify(b"tampered", &sig, &pk), Err(OpError::VerifyFailed));
    }

    #[test]
    fn wrong_key_fails_verify() {
        let (sk, _) = generate_keypair();
        let (_, other_pub) = generate_keypair();
        let sig = sign(b"m", &sk).unwrap();
        assert_eq!(verify(b"m", &sig, &other_pub), Err(OpError::VerifyFailed));
    }

    #[test]
    fn scope_check() {
        assert!(validate_scope("/tmp/asmodeus-canary/x"));
        assert!(!validate_scope("/etc/passwd"));
    }
}
