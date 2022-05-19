mod errors;
pub use errors::*;

/// Named ECC curves.
///
/// `Secp256r1` and `X25519` are supported.
#[derive(Clone, Copy, PartialEq)]
pub enum NamedGroup {
    X25519,
    X448,
    Secp256r1,
    Secp384r1,
    Secp521r1,
}

pub type KemScheme = NamedGroup;

/// Get the length of the private key for the given [`KemScheme`] in bytes.
pub fn kem_priv_len(ks: &KemScheme) -> usize {
    dh_priv_len(ks)
}

/// Get the length of the public key for the given [`KemScheme`] in bytes.
pub fn kem_pub_len(ks: &KemScheme) -> usize {
    dh_pub_len(ks)
}

/// Hash algorithms
///
/// Only `SHA256` is supported.
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

/// AEAD algorithms
///
/// `Chacha20Poly1305` and `Aes128Gcm` are supported.
#[derive(Clone, Copy, PartialEq)]
pub enum AeadAlgorithm {
    Chacha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

/// Signature algorithms
///
/// `ED25519` and `EcdsaSecp256r1Sha256` are supported.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SignatureScheme {
    ED25519,
    EcdsaSecp256r1Sha256,
    RsaPssRsaSha256,
}

// === Helper functions to get the length of different configurations. === //

/// Get the length of the digest for the given [`HashAlgorithm`] in bytes.
pub fn hash_len(ha: &HashAlgorithm) -> usize {
    match ha {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::SHA384 => 48,
        HashAlgorithm::SHA512 => 64,
    }
}

/// Get the length of the tag for the given [`HashAlgorithm`] in bytes.
pub fn hmac_tag_len(ha: &HashAlgorithm) -> usize {
    match ha {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::SHA384 => 48,
        HashAlgorithm::SHA512 => 64,
    }
}

/// Get the length of the key for the given [`AeadAlgorithm`] in bytes.
pub fn ae_key_len(ae: &AeadAlgorithm) -> usize {
    match ae {
        AeadAlgorithm::Chacha20Poly1305 => 32,
        AeadAlgorithm::Aes128Gcm => 16,
        AeadAlgorithm::Aes256Gcm => 16,
    }
}

/// Get the length of the nonce for the given [`AeadAlgorithm`] in bytes.
pub fn ae_iv_len(ae: &AeadAlgorithm) -> usize {
    match ae {
        AeadAlgorithm::Chacha20Poly1305 => 12,
        AeadAlgorithm::Aes128Gcm => 12,
        AeadAlgorithm::Aes256Gcm => 12,
    }
}

/// Get the length of the private key for the given [`NamedGroup`] in bytes.
pub fn dh_priv_len(gn: &NamedGroup) -> usize {
    match gn {
        NamedGroup::X25519 => 32,
        NamedGroup::X448 => 56,
        NamedGroup::Secp256r1 => 32,
        NamedGroup::Secp384r1 => 48,
        NamedGroup::Secp521r1 => 66,
    }
}

/// Get the length of the public key for the given [`NamedGroup`] in bytes.
pub fn dh_pub_len(gn: &NamedGroup) -> usize {
    match gn {
        NamedGroup::X25519 => 32,
        NamedGroup::X448 => 56,
        NamedGroup::Secp256r1 => 64,
        NamedGroup::Secp384r1 => 96,
        NamedGroup::Secp521r1 => 132,
    }
}
