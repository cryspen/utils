use crate::*;

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

fn validate_signature(r: &P256Scalar, s: &P256Scalar) -> EmptyResult {
    let r_value = r.to_public_byte_seq_be();
    let s_value = s.to_public_byte_seq_be();
    let order = Seq::<u8>::from_native_slice(&[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ]);
    let zero = Seq::<u8>::from_native_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    if order == s_value || order == r_value || s_value == zero || r_value == zero {
        EmptyResult::Err(VERIFY_FAILED)
    } else {
        EmptyResult::Ok(())
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
    validate_signature(&r, &s)?;
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
