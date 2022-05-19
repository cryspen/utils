use crate::*;

/// Convert a DH secret key to the corresponding public key in the given group
pub fn secret_to_public(group_name: &NamedGroup, x: &DhSk) -> DhPkResult {
    match group_name {
        NamedGroup::Secp256r1 => match p256_point_mul_base(P256Scalar::from_byte_seq_be(x)) {
            AffineResult::Ok((x, y)) => {
                DhPkResult::Ok(x.to_byte_seq_be().concat(&y.to_byte_seq_be()))
            }
            AffineResult::Err(_) => DhPkResult::Err(CRYPTO_ERROR),
        },
        NamedGroup::X25519 => DhPkResult::Ok(DhPk::from_seq(&x25519_secret_to_public(
            X25519SerializedScalar::from_seq(x),
        ))),
        NamedGroup::X448 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

fn p256_check_point_len(p: &DhPk) -> EmptyResult {
    if p.len() != 64 {
        EmptyResult::Err(CRYPTO_ERROR)
    } else {
        EmptyResult::Ok(())
    }
}

fn p256_ecdh(x: &DhSk, y: &DhPk) -> CryptoByteSeqResult {
    p256_check_point_len(y)?;
    let pk = (
        P256FieldElement::from_byte_seq_be(&y.slice_range(0..32)),
        P256FieldElement::from_byte_seq_be(&y.slice_range(32..64)),
    );
    match p256_point_mul(P256Scalar::from_byte_seq_be(x), pk) {
        AffineResult::Ok((x, y)) => {
            CryptoByteSeqResult::Ok(x.to_byte_seq_be().concat(&y.to_byte_seq_be()))
        }
        AffineResult::Err(_) => CryptoByteSeqResult::Err(CRYPTO_ERROR),
    }
}

/// Compute the ECDH on [`DhSk`] and [`DhPk`].
pub fn ecdh(group_name: &NamedGroup, x: &DhSk, y: &DhPk) -> CryptoByteSeqResult {
    match group_name {
        NamedGroup::Secp256r1 => p256_ecdh(x, y),
        NamedGroup::X25519 => CryptoByteSeqResult::Ok(DhPk::from_seq(&x25519_scalarmult(
            X25519SerializedScalar::from_seq(x),
            X25519SerializedPoint::from_seq(y),
        ))),
        NamedGroup::X448 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Verify that k != 0 && k < ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
pub fn valid_p256_private_key(k: &ByteSeq) -> bool {
    let k_element = P256Scalar::from_byte_seq_be(k);
    let k_element_bytes = k_element.to_byte_seq_be();
    let mut valid = k_element_bytes.len() == k.len();
    let mut all_zero = true;
    if valid {
        for i in 0..k.len() {
            if !k[i].equal(U8(0u8)) {
                all_zero = false;
            }
            if !k_element_bytes[i].equal(k[i]) {
                valid = false;
            }
        }
    }
    valid && !all_zero
}

/// Validate a candidate [`DhSk`].
///
/// Return `true` if `bytes` is a valid private key for the given group and `false`
/// otherwise.
pub fn valid_private_key(named_group: &NamedGroup, bytes: &DhSk) -> bool {
    match named_group {
        NamedGroup::X25519 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::X448 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::Secp256r1 => valid_p256_private_key(bytes),
        NamedGroup::Secp384r1 => false,
        NamedGroup::Secp521r1 => false,
    }
}

/// Parse a public key and return it if it's valid.
pub fn parse_public_key(named_group: &NamedGroup, bytes: &DhPk) -> Result<DhPk, CryptoError> {
    match named_group {
        NamedGroup::X25519 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::X448 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::Secp256r1 => Result::<DhPk, CryptoError>::Ok(bytes.slice(1, bytes.len() - 1)),
        NamedGroup::Secp384r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
    }
}
