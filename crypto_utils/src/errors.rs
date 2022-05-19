pub type CryptoError = u8;

pub const CRYPTO_ERROR: CryptoError = 1u8;
pub const HKDF_ERROR: CryptoError = 2u8;
pub const INSUFFICIENT_ENTROPY: CryptoError = 3u8;
pub const INVALID_CERT: CryptoError = 4u8;
pub const MAC_FAILED: CryptoError = 5u8;
pub const UNSUPPORTED_ALGORITHM: CryptoError = 6u8;
pub const VERIFY_FAILED: CryptoError = 7u8;
