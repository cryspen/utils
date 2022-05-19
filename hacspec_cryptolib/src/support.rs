use crate::*;

/// Check if a [`NamedGroup`] is supported.
pub fn named_group_support(named_group: &NamedGroup) -> EmptyResult {
    match named_group {
        NamedGroup::X25519 => EmptyResult::Ok(()),
        NamedGroup::Secp256r1 => EmptyResult::Ok(()),
        NamedGroup::X448 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [`HashAlgorithm`] is supported.
pub fn hash_support(hash: &HashAlgorithm) -> EmptyResult {
    match hash {
        HashAlgorithm::SHA256 => EmptyResult::Ok(()),
        HashAlgorithm::SHA384 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [`AeadAlgorithm`] is supported.
pub fn aead_support(aead: &AeadAlgorithm) -> EmptyResult {
    match aead {
        AeadAlgorithm::Chacha20Poly1305 => EmptyResult::Ok(()),
        AeadAlgorithm::Aes128Gcm => EmptyResult::Ok(()),
        AeadAlgorithm::Aes256Gcm => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [`SignatureScheme`] is supported.
pub fn signature_support(signature: &SignatureScheme) -> EmptyResult {
    match signature {
        SignatureScheme::ED25519 => EmptyResult::Ok(()),
        SignatureScheme::EcdsaSecp256r1Sha256 => EmptyResult::Ok(()),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}
