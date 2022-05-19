use crate::*;

/// Compute the public key for a private key of the given [`KemScheme`].
pub fn kem_priv_to_pub(ks: &KemScheme, sk: &KemSk) -> CryptoByteSeqResult {
    secret_to_public(ks, sk)
}

/// Generate a key pair for the [`KemScheme`] based on the provided [`Entropy`].
///
/// The provided [`Entropy`] must be at least of length [`kem_priv_len()`].
pub fn kem_keygen(ks: &KemScheme, ent: Entropy) -> CryptoByteSeq2Result {
    let mut result = CryptoByteSeq2Result::Err(INSUFFICIENT_ENTROPY);
    if ent.len() >= kem_priv_len(ks) {
        let sk = KemSk::from_seq(&ent.slice_range(0..kem_priv_len(ks)));
        let pk = kem_priv_to_pub(ks, &sk)?;
        result = CryptoByteSeq2Result::Ok((sk, pk));
    }
    result
}

/// Encapsulate a shared secret to the provided `pk` and return the `(Key, Enc)` tuple.
pub fn kem_encap(ks: &KemScheme, pk: &KemPk, ent: Entropy) -> CryptoByteSeq2Result {
    let (x, gx) = kem_keygen(ks, ent)?;
    let gxy = ecdh(ks, &x, pk)?;
    CryptoByteSeq2Result::Ok((gxy, gx))
}

/// Decapsulate the shared secret in `ct` using the private key `sk`.
pub fn kem_decap(ks: &KemScheme, ct: &ByteSeq, sk: KemSk) -> CryptoByteSeqResult {
    let gxy = ecdh(ks, &sk, ct)?;
    CryptoByteSeqResult::Ok(gxy)
}
