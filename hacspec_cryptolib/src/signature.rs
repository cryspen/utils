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

// Very basic ASN.1 parser to read the ECDSA public key from an X.509 certificate.
pub fn verification_key_from_cert(cert: &ByteSeq) -> Result<VerificationKey, CryptoError> {
    // cert is an ASN.1 sequence. Take the first sequence inside the outer.
    // Skip 1 + length bytes
    let skip = 2 + get_length_length(&cert.slice_range(1..cert.len())) + 1;
    let seq1_len_len = get_length_length(&cert.slice_range(skip..cert.len()));
    let skip = skip + 1;
    let seq1_len = get_length(&cert.slice(skip, cert.len() - skip), seq1_len_len);
    let mut seq1 = cert.slice_range(skip + seq1_len_len..skip + seq1_len_len + seq1_len);

    // Read sequences until we find the ecPublicKey (we don't support anything else right now)
    let mut pk = VerificationKey::new(0);
    for _ in 0..seq1.len() {
        // FIXME: we really need a break statement.
        if seq1.len() > 0 {
            let element_type = U8::declassify(seq1[0]);
            seq1 = seq1.slice(1, seq1.len() - 1);
            let len_len = get_length_length(&seq1);
            let mut len = get_short_length(&seq1);
            seq1 = seq1.slice(1, seq1.len() - 1);
            if len_len != 0 {
                len = get_length(&seq1, len_len) + len_len;
            }
            // XXX: Unfortunately we can't break so we don't go in here if we have
            //      the pk already.
            if element_type == 0x30u8 && pk.len() == 0 {
                // peek into this sequence to see if sequence again with an ecPublicKey
                // as first element
                let seq2 = seq1.slice(len_len, len);
                let element_type = U8::declassify(seq2[0]);
                let seq2 = seq2.slice(1, seq2.len() - 1);
                if element_type == 0x30u8 {
                    let len_len = get_length_length(&seq2);
                    if len_len == 0 {
                        let oid_len = get_short_length(&seq2);
                        if oid_len >= 9 {
                            // ecPublicKey oid incl tag: 06 07 2A 86 48 CE 3D 02 01
                            // FIXME: This shouldn't be necessary. Instead public_byte_seq!
                            //        should be added to the typechecker. #136
                            let expected = ByteSeq::from_seq(&EcOidTag(secret_bytes!([
                                0x06u8, 0x07u8, 0x2Au8, 0x86u8, 0x48u8, 0xCEu8, 0x3Du8, 0x02u8,
                                0x01u8
                            ])));
                            let oid = seq2.slice(1, 9);
                            let mut ec_pk_oid = true;
                            for i in 0..9 {
                                let oid_byte_equal =
                                    U8::declassify(oid[i]) == U8::declassify(expected[i]);
                                ec_pk_oid = ec_pk_oid && oid_byte_equal;
                            }
                            if ec_pk_oid {
                                // We have an ecPublicKey, skip the inner sequences
                                // and read the public key from the bit string
                                let bit_string = seq2.slice(oid_len + 1, seq2.len() - oid_len - 1);
                                // We only support uncompressed points
                                if U8::declassify(bit_string[0]) == 0x03u8 {
                                    let pk_len = declassify_usize_from_U8(bit_string[1]); // 42
                                    let _zeroes = declassify_usize_from_U8(bit_string[2]); // 00
                                    let _uncompressed = declassify_usize_from_U8(bit_string[3]); // 04
                                    pk = bit_string.slice(4, pk_len - 2);
                                }
                            }
                        }
                    }
                }
            }
            seq1 = seq1.slice(len, seq1.len() - len);
        }
    }
    if pk.len() == 0 {
        CryptoByteSeqResult::Err(INVALID_CERT)
    } else {
        CryptoByteSeqResult::Ok(pk)
    }
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

/// Verify the signature on the `payload` with the given [`VerificationKey`] and
/// [`SignatureScheme`].
pub fn verify(
    sa: &SignatureScheme,
    pk: &VerificationKey,
    payload: &ByteSeq,
    sig: &ByteSeq,
) -> EmptyResult {
    match sa {
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_verify(pk, payload, sig),
        SignatureScheme::ED25519 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}
