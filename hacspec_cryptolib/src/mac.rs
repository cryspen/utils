use crate::*;

/// Compute tha HMAC tag on the given `payload` with the [`HashAlgorithm`] and [`MacKey`].
pub fn hmac_tag(ha: &HashAlgorithm, mk: &MacKey, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => CryptoByteSeqResult::Ok(HMAC::from_seq(&hmac(mk, payload))),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

fn check_tag_len(a: &HMAC, b: &HMAC) -> EmptyResult {
    if a.len() == b.len() {
        EmptyResult::Ok(())
    } else {
        EmptyResult::Err(MAC_FAILED)
    }
}

fn check_bytes(a: U8, b: U8) -> EmptyResult {
    if !a.equal(b) {
        EmptyResult::Err(MAC_FAILED)
    } else {
        EmptyResult::Ok(())
    }
}

/// Verify the validity of a given [`HMAC`] tag.
///
/// Returns a [`CryptoError`] if the tag is invalid.
pub fn hmac_verify(ha: &HashAlgorithm, mk: &MacKey, payload: &ByteSeq, t: &HMAC) -> EmptyResult {
    let my_hmac = hmac_tag(ha, mk, payload)?;
    check_tag_len(t, &my_hmac)?;
    for i in 0..t.len() {
        check_bytes(my_hmac[i], t[i])?;
    }
    EmptyResult::Ok(())
}
