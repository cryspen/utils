use crate::*;

fn aes128_encrypt(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let (ctxt, tag) = encrypt_aes128(Key128::from_seq(k), AesNonce::from_seq(iv), ad, payload);
    CryptoByteSeqResult::Ok(ctxt.concat(&tag))
}

fn chacha_encrypt(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let (ctxt, tag) =
        chacha20_poly1305_encrypt(ChaChaKey::from_seq(k), ChaChaIV::from_seq(iv), ad, payload);
    CryptoByteSeqResult::Ok(ctxt.concat(&tag))
}

/// AEAD encrypt the `payload` with the [`AeadAlgorithm`].
pub fn aead_encrypt(
    a: &AeadAlgorithm,
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match a {
        AeadAlgorithm::Aes128Gcm => aes128_encrypt(k, iv, payload, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        AeadAlgorithm::Chacha20Poly1305 => chacha_encrypt(k, iv, payload, ad),
    }
}

fn aes128_decrypt(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match decrypt_aes128(
        Key128::from_seq(k),
        AesNonce::from_seq(iv),
        ad,
        &ciphertext.slice_range(0..ciphertext.len() - 16),
        Gf128Tag::from_seq(&ciphertext.slice_range(ciphertext.len() - 16..ciphertext.len())),
    ) {
        AesGcmByteSeqResult::Ok(m) => CryptoByteSeqResult::Ok(m),
        AesGcmByteSeqResult::Err(_) => CryptoByteSeqResult::Err(MAC_FAILED),
    }
}

fn chacha_decrypt(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match chacha20_poly1305_decrypt(
        ChaChaKey::from_seq(k),
        ChaChaIV::from_seq(iv),
        ad,
        &ciphertext.slice_range(0..ciphertext.len() - 16),
        Poly1305Tag::from_seq(&ciphertext.slice_range(ciphertext.len() - 16..ciphertext.len())),
    ) {
        ByteSeqResult::Ok(ptxt) => CryptoByteSeqResult::Ok(ptxt),
        ByteSeqResult::Err(_) => CryptoByteSeqResult::Err(MAC_FAILED),
    }
}

/// AEAD decrypt the `ciphertext` with the [`AeadAlgorithm`] and return the payload.
pub fn aead_decrypt(
    a: &AeadAlgorithm,
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    match a {
        AeadAlgorithm::Aes128Gcm => aes128_decrypt(k, iv, ciphertext, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        AeadAlgorithm::Chacha20Poly1305 => chacha_decrypt(k, iv, ciphertext, ad),
    }
}
