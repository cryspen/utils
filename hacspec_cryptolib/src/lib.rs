//! # hacspec cryptolib
//!
//! This crate wraps all the commonly used hacspec cryptographic primitives used
//! by protocols such as TLS, HPKE or MLS.
//!
//! The crate itself is written in hacspec as well.
pub use crypto_utils::*;
use hacspec_lib::*;

// === Import all the hacspec crypto primitives. === //
use hacspec_aes::*;
use hacspec_aes128_gcm::*;
use hacspec_chacha20::*;
use hacspec_chacha20poly1305::*;
use hacspec_curve25519::*;
use hacspec_ecdsa_p256_sha256::*;
use hacspec_gf128::*;
use hacspec_hkdf::*;
use hacspec_hmac::*;
use hacspec_p256::*;
use hacspec_poly1305::*;
use hacspec_sha256::*;

// === Modules === //

mod aead;
mod ecdh;
mod kem;
mod mac;
mod signature;
mod support;
mod types;

pub use aead::*;
pub use ecdh::*;
pub use kem::*;
pub use mac::*;
pub use signature::*;
pub use support::*;
pub use types::*;

/// Get an all-zero key of length corresponding to the digest of the [`HashAlgorithm`].
pub fn zero_key(ha: &HashAlgorithm) -> Key {
    Key::new(hash_len(ha) as usize)
}

/// Hash the `payload` with [`HashAlgorithm`].
pub fn hash(ha: &HashAlgorithm, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => CryptoByteSeqResult::Ok(Digest::from_seq(&sha256(payload))),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// HKDF Extract.
pub fn hkdf_extract(ha: HashAlgorithm, k: &Key, salt: &Key) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => CryptoByteSeqResult::Ok(Key::from_seq(&extract(salt, k))),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// HKDF Expand.
pub fn hkdf_expand(ha: HashAlgorithm, k: &Key, info: &ByteSeq, len: usize) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => match expand(k, info, len) {
            HkdfByteSeqResult::Ok(b) => CryptoByteSeqResult::Ok(b),
            HkdfByteSeqResult::Err(_) => CryptoByteSeqResult::Err(HKDF_ERROR),
        },
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}
