use crate::*;

// Some ASN.1 helper functions
fn get_length_length(b: &ByteSeq) -> usize {
    if U8::declassify(b[0]) >> 7 == 1u8 {
        declassify_usize_from_U8(b[0] & U8(0x7fu8))
    } else {
        0
    }
}

fn get_length(b: &ByteSeq, len: usize) -> usize {
    declassify_u32_from_U32(U32_from_be_bytes(U32Word::from_slice(b, 0, len))) as usize
        >> ((4 - len) * 8)
}

fn get_short_length(b: &ByteSeq) -> usize {
    declassify_usize_from_U8(b[0] & U8(0x7fu8))
}

fn concat_signature(r: P256Scalar, s: P256Scalar) -> Result<Signature, CryptoError> {
    let signature = Signature::new(0)
        .concat_owned(r.to_byte_seq_be())
        .concat_owned(s.to_byte_seq_be());
    CryptoByteSeqResult::Ok(signature)
}

fn p256_sign(
    ps: &SignatureKey,
    payload: &ByteSeq,
    entropy: Entropy,
) -> Result<Signature, CryptoError> {
    let (entropy, _) = entropy.split_off(32);
    // XXX: from_byte_seq_be doesn't check validity of the input bytes yet.
    //      See https://github.com/hacspec/hacspec/issues/138
    let nonce = P256Scalar::from_byte_seq_be(&entropy);
    match ecdsa_p256_sha256_sign(payload, P256Scalar::from_byte_seq_be(ps), nonce) {
        // The ASN.1 encoding happens later on the outside.
        P256SignatureResult::Ok((r, s)) => concat_signature(r, s),
        P256SignatureResult::Err(_) => CryptoByteSeqResult::Err(CRYPTO_ERROR),
    }
}

/// Sign the `payload` with the given [`SignatureKey`] and [`SignatureScheme`].
pub fn sign(
    sa: &SignatureScheme,
    ps: &SignatureKey,
    payload: &ByteSeq,
    ent: Entropy,
) -> Result<Signature, CryptoError> {
    match sa {
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_sign(ps, payload, ent),
        SignatureScheme::ED25519 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

fn p256_verify(pk: &VerificationKey, payload: &ByteSeq, sig: &ByteSeq) -> EmptyResult {
    println!(
        "P256 verification with\n\tpk {}\n of\t\n{}",
        pk.to_hex(),
        payload.to_hex()
    );
    let (pk_x, pk_y) = (
        P256FieldElement::from_byte_seq_be(&pk.slice(0, 32)),
        P256FieldElement::from_byte_seq_be(&pk.slice(32, 32)),
    );
    let (r, s) = (
        P256Scalar::from_byte_seq_be(&sig.slice(0, 32)),
        P256Scalar::from_byte_seq_be(&sig.slice(32, 32)),
    );
    match ecdsa_p256_sha256_verify(payload, (pk_x, pk_y), (r, s)) {
        P256VerifyResult::Ok(()) => EmptyResult::Ok(()),
        P256VerifyResult::Err(_) => EmptyResult::Err(VERIFY_FAILED),
    }
}

fn ecdsa_key(pk: &PublicVerificationKey) -> VerificationKeyResult {
    if let PublicVerificationKey::EcDsa(pk) = pk {
        VerificationKeyResult::Ok(pk.clone())
    } else {
        VerificationKeyResult::Err(INCONSISTENT_ARGUMENTS)
    }
}

fn rsa_key(pk: &PublicVerificationKey) -> RsaVerificationKeyResult {
    if let PublicVerificationKey::Rsa(pk) = pk {
        RsaVerificationKeyResult::Ok(pk.clone())
    } else {
        RsaVerificationKeyResult::Err(INCONSISTENT_ARGUMENTS)
    }
}

/// Verify the signature on the `payload` with the given [`VerificationKey`] and
/// [`SignatureScheme`].
pub fn verify(
    sa: &SignatureScheme,
    pk: &PublicVerificationKey,
    payload: &ByteSeq,
    sig: &ByteSeq,
) -> EmptyResult {
    match sa {
        SignatureScheme::EcdsaSecp256r1Sha256 => {
            let pk = ecdsa_key(pk)?;
            p256_verify(&pk, payload, sig)
        }
        SignatureScheme::ED25519 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => {
            let _pk = rsa_key(pk)?;
            todo!("Implement RSA PSS verification in hacspec")
        }
    }
}
