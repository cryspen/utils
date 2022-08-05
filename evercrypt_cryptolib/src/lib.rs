//! # evercrypt cryptolib
//!
//! This crate wraps all cryptographic primitives from [evercrypt] commonly used by protocols such
//! as TLS, HPKE or MLS.
//!
//! It is a drop-in replacement for the `hacspec_cryptolib` exposing the same API.
use hacspec_lib::*;

use evercrypt::prelude::*;

pub use crypto_utils::*;

// === Types === //
pub type CryptoError = u8;

pub type Key = ByteSeq;
pub type PSK = Key;
pub type Digest = ByteSeq;
pub type MacKey = ByteSeq;
pub type HMAC = ByteSeq;

pub type SignatureKey = ByteSeq;
pub type VerificationKey = ByteSeq;
pub type Signature = ByteSeq;

pub type AeadKey = ByteSeq;
pub type AeadIv = ByteSeq;
pub type AeadKeyIV = (AeadKey, AeadIv);

pub type Entropy = ByteSeq;

pub type DhSk = ByteSeq;
pub type DhPk = ByteSeq;
pub type KemScheme = NamedGroup;
pub type KemSk = ByteSeq;
pub type KemPk = ByteSeq;

bytes!(EcOidTag, 9);
bytes!(Random32, 32);

type DhPkResult = Result<DhPk, CryptoError>;
type EmptyResult = Result<(), CryptoError>;
type CryptoByteSeqResult = Result<ByteSeq, CryptoError>;
type CryptoByteSeq2Result = Result<(ByteSeq, ByteSeq), CryptoError>;

mod asn1;
pub use asn1::*;

// === Allow checking support for algorithms === //
/// Check if a [NamedGroup] is supported.
pub fn named_group_support(named_group: &NamedGroup) -> EmptyResult {
    match named_group {
        NamedGroup::X25519 => EmptyResult::Ok(()),
        NamedGroup::Secp256r1 => EmptyResult::Ok(()),
        NamedGroup::X448 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [HashAlgorithm] is supported.
pub fn hash_support(hash: &HashAlgorithm) -> EmptyResult {
    match hash {
        HashAlgorithm::SHA256 => EmptyResult::Ok(()),
        HashAlgorithm::SHA384 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [AeadAlgorithm] is supported.
pub fn aead_support(aead: &AeadAlgorithm) -> EmptyResult {
    match aead {
        AeadAlgorithm::Chacha20Poly1305 => EmptyResult::Ok(()),
        AeadAlgorithm::Aes128Gcm => EmptyResult::Ok(()),
        AeadAlgorithm::Aes256Gcm => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Check if a [SignatureScheme] is supported.
pub fn signature_support(signature: &SignatureScheme) -> EmptyResult {
    match signature {
        SignatureScheme::ED25519 => EmptyResult::Ok(()),
        SignatureScheme::EcdsaSecp256r1Sha256 => EmptyResult::Ok(()),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Get an all-zero key of length corresponding to the digest of the [`HashAlgorithm`].
pub fn zero_key(ha: &HashAlgorithm) -> Key {
    Key::new(hash_len(ha) as usize)
}

// === ECDH === //

// Unsafe ECDH functions converting hacspec types to native Rust types for
// evercrypt.
// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_base_unsafe(x: &DhSk) -> CryptoByteSeqResult {
    match p256_base(&x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_unsafe(x: &DhSk, p: &DhPk) -> CryptoByteSeqResult {
    match p256(&p.to_native(), &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn x25519_base_unsafe(x: &DhSk) -> CryptoByteSeqResult {
    match ecdh_derive_base(EcdhMode::X25519, &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}
// FIXME: #98 add #[unsafe_hacspec] attribute
fn x25519_unsafe(x: &DhSk, p: &DhPk) -> CryptoByteSeqResult {
    match ecdh_derive(EcdhMode::X25519, &p.to_native(), &x.to_native()) {
        Ok(p) => Ok(DhPk::from_public_slice(&p)),
        Err(_) => Err(CRYPTO_ERROR),
    }
}

/// Convert a DH secret key to the corresponding public key in the given group
pub fn secret_to_public(group_name: &NamedGroup, x: &DhSk) -> DhPkResult {
    match group_name {
        NamedGroup::Secp256r1 => p256_base_unsafe(x),
        NamedGroup::X25519 => x25519_base_unsafe(x),
        NamedGroup::X448 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => DhPkResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Compute the ECDH on [`DhSk`] and [`DhPk`].
pub fn ecdh(group_name: &NamedGroup, x: &DhSk, y: &DhPk) -> CryptoByteSeqResult {
    match group_name {
        NamedGroup::Secp256r1 => p256_unsafe(x, y),
        NamedGroup::X25519 => x25519_unsafe(x, y),
        NamedGroup::X448 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp384r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// Validate a candidate [`DhSk`].
///
/// Return `true` if `bytes` is a valid private key for the given group and `false`
/// otherwise.
pub fn valid_private_key(named_group: &NamedGroup, bytes: &DhSk) -> bool {
    match named_group {
        NamedGroup::X25519 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::X448 => bytes.len() == dh_priv_len(named_group),
        NamedGroup::Secp256r1 => match p256::validate_sk(&bytes.to_native()) {
            Ok(_) => true,
            Err(_) => false,
        },
        NamedGroup::Secp384r1 => false,
        NamedGroup::Secp521r1 => false,
    }
}

/// Parse a public key and return it if it's valid.
pub fn parse_public_key(named_group: &NamedGroup, bytes: &DhPk) -> Result<DhPk, CryptoError> {
    match named_group {
        NamedGroup::X25519 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::X448 => Result::<DhPk, CryptoError>::Ok(bytes.clone()),
        NamedGroup::Secp256r1 => match p256::validate_pk(&bytes.to_native()) {
            Ok(pk) => Result::<DhPk, CryptoError>::Ok(ByteSeq::from_public_slice(&pk)),
            Err(_) => Result::<DhPk, CryptoError>::Err(CRYPTO_ERROR),
        },
        NamedGroup::Secp384r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
        NamedGroup::Secp521r1 => Result::<DhPk, CryptoError>::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === Key Encapsulation === //

/// Get the length of the private key for the given [`KemScheme`] in bytes.
pub fn kem_priv_len(ks: &KemScheme) -> usize {
    dh_priv_len(ks)
}

/// Get the length of the public key for the given [`KemScheme`] in bytes.
pub fn kem_pub_len(ks: &KemScheme) -> usize {
    dh_pub_len(ks)
}

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

// === Hashing === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn sha256_unsafe(payload: &ByteSeq) -> CryptoByteSeqResult {
    Ok(Digest::from_public_slice(&evercrypt::digest::hash(
        DigestMode::Sha256,
        &payload.to_native(),
    )))
}

/// Hash the `payload` with [`HashAlgorithm`].
pub fn hash(ha: &HashAlgorithm, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => sha256_unsafe(payload),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === HMAC === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hmac_sha256_unsafe(mk: &MacKey, payload: &ByteSeq) -> CryptoByteSeqResult {
    Ok(HMAC::from_public_slice(&evercrypt::hmac::hmac(
        HmacMode::Sha256,
        &mk.to_native(),
        &payload.to_native(),
        None,
    )))
}

/// Compute tha HMAC tag on the given `payload` with the [`HashAlgorithm`] and [`MacKey`].
pub fn hmac_tag(ha: &HashAlgorithm, mk: &MacKey, payload: &ByteSeq) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hmac_sha256_unsafe(mk, payload),
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

// === Signatures === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_sha256_sign_unsafe(
    ps: &SignatureKey,
    payload: &ByteSeq,
    random: &Entropy,
) -> CryptoByteSeqResult {
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&ps.to_native());
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&random.to_native());
    match p256_sign(DigestMode::Sha256, &payload.to_native(), &sk, &nonce) {
        // FIXME: this must encode the signature with ASN.1
        Ok(s) => Ok(Signature::from_public_slice(&s.raw())),
        Err(_e) => Err(CRYPTO_ERROR),
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
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_sha256_sign_unsafe(ps, payload, &ent),
        SignatureScheme::ED25519 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn p256_sha256_verify_unsafe(
    pk: &VerificationKey,
    payload: &ByteSeq,
    sig: &ByteSeq,
) -> EmptyResult {
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_native());
    let result = p256_verify(
        DigestMode::Sha256,
        &payload.to_native(),
        &pk.to_native(),
        &EcdsaSignature::from_bytes(&sig_bytes),
    );
    if let Ok(r) = result {
        if r {
            Ok(())
        } else {
            Err(VERIFY_FAILED)
        }
    } else {
        Err(VERIFY_FAILED)
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
        SignatureScheme::EcdsaSecp256r1Sha256 => p256_sha256_verify_unsafe(pk, payload, sig),
        SignatureScheme::ED25519 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
        SignatureScheme::RsaPssRsaSha256 => EmptyResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === HKDF === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hkdf_extract_unsafe(k: &Key, salt: &Key) -> CryptoByteSeqResult {
    Ok(Key::from_public_slice(&hkdf::extract(
        HmacMode::Sha256,
        &salt.to_native(),
        &k.to_native(),
    )))
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn hkdf_expand_unsafe(k: &Key, info: &ByteSeq, len: usize) -> CryptoByteSeqResult {
    Ok(Key::from_public_slice(&hkdf::expand(
        HmacMode::Sha256,
        &k.to_native(),
        &info.to_native(),
        len,
    )))
}

/// HKDF Extract.
pub fn hkdf_extract(ha: &HashAlgorithm, k: &Key, salt: &Key) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hkdf_extract_unsafe(k, salt),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

/// HKDF Expand.
pub fn hkdf_expand(ha: &HashAlgorithm, k: &Key, info: &ByteSeq, len: usize) -> CryptoByteSeqResult {
    match ha {
        HashAlgorithm::SHA256 => hkdf_expand_unsafe(k, info, len),
        HashAlgorithm::SHA384 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
        HashAlgorithm::SHA512 => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// === AEAD === //

// FIXME: #98 add #[unsafe_hacspec] attribute
fn aesgcm_encrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::encrypt(
        AeadMode::Aes128Gcm,
        &k.to_native(),
        &payload.to_native(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok((c, t)) => Ok(ByteSeq::from_public_slice(&c).concat(&ByteSeq::from_public_slice(&t))),
        Err(_e) => Err(CRYPTO_ERROR),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn chachapoly_encrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    payload: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::encrypt(
        AeadMode::Chacha20Poly1305,
        &k.to_native(),
        &payload.to_native(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok((c, t)) => Ok(ByteSeq::from_public_slice(&c).concat(&ByteSeq::from_public_slice(&t))),
        Err(_e) => Err(CRYPTO_ERROR),
    }
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
        AeadAlgorithm::Aes128Gcm => aesgcm_encrypt_unsafe(k, iv, payload, ad),
        AeadAlgorithm::Chacha20Poly1305 => chachapoly_encrypt_unsafe(k, iv, payload, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn aesgcm_decrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::decrypt(
        AeadMode::Aes128Gcm,
        &k.to_native(),
        &ciphertext
            .slice_range(0..ciphertext.len() - 16)
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &ciphertext
            .slice_range(ciphertext.len() - 16..ciphertext.len())
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok(ptxt) => Ok(ByteSeq::from_public_slice(&ptxt)),
        Err(_e) => Err(MAC_FAILED),
    }
}

// FIXME: #98 add #[unsafe_hacspec] attribute
fn chachapoly_decrypt_unsafe(
    k: &AeadKey,
    iv: &AeadIv,
    ciphertext: &ByteSeq,
    ad: &ByteSeq,
) -> CryptoByteSeqResult {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&iv.to_native());
    match evercrypt::aead::decrypt(
        AeadMode::Chacha20Poly1305,
        &k.to_native(),
        &ciphertext
            .slice_range(0..ciphertext.len() - 16)
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &ciphertext
            .slice_range(ciphertext.len() - 16..ciphertext.len())
            .iter()
            .map(|&x| x.declassify())
            .collect::<Vec<u8>>(),
        &nonce,
        &ad.to_native(),
    ) {
        Ok(ptxt) => Ok(ByteSeq::from_public_slice(&ptxt)),
        Err(_e) => Err(MAC_FAILED),
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
        AeadAlgorithm::Aes128Gcm => aesgcm_decrypt_unsafe(k, iv, ciphertext, ad),
        AeadAlgorithm::Chacha20Poly1305 => chachapoly_decrypt_unsafe(k, iv, ciphertext, ad),
        AeadAlgorithm::Aes256Gcm => CryptoByteSeqResult::Err(UNSUPPORTED_ALGORITHM),
    }
}
