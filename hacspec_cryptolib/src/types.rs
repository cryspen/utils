//! hacspec types
use crate::*;

pub type Key = ByteSeq;
pub type PSK = Key;
pub type Digest = ByteSeq;
pub type MacKey = ByteSeq;
pub type HMAC = ByteSeq;

pub type SignatureKey = ByteSeq;
pub type VerificationKey = ByteSeq;
pub type RsaVerificationKey = (ByteSeq, ByteSeq); // N, e

#[derive(Debug)]
pub enum PublicVerificationKey {
    EcDsa(VerificationKey),  // Uncompressed point 0x04...
    Rsa(RsaVerificationKey), // N, e
}

pub type Signature = ByteSeq;

pub type AeadKey = ByteSeq;
pub type AeadIv = ByteSeq;
pub type AeadKeyIV = (AeadKey, AeadIv);

pub type Entropy = ByteSeq;

pub type DhSk = ByteSeq;
pub type DhPk = ByteSeq;
pub type KemSk = ByteSeq;
pub type KemPk = ByteSeq;

bytes!(EcOidTag, 9);
bytes!(Random32, 32);

pub(crate) type DhPkResult = Result<DhPk, CryptoError>;
pub(crate) type EmptyResult = Result<(), CryptoError>;
pub(crate) type CryptoByteSeqResult = Result<ByteSeq, CryptoError>;
pub(crate) type CryptoByteSeq2Result = Result<(ByteSeq, ByteSeq), CryptoError>;
