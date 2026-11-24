use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

#[inline(always)]
pub fn deser<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CryptoKeystoreError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[inline(always)]
pub fn ser<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CryptoKeystoreError> {
    Ok(postcard::to_stdvec(value)?)
}

/// Decode a value from exactly these bytes.
///
/// Unlike [`deser`], this fails if any bytes are left over.
pub(crate) fn deser_exact<T: DeserializeOwned>(bytes: &[u8]) -> CryptoKeystoreResult<T> {
    let (value, rest) = postcard::take_from_bytes(bytes)?;
    if !rest.is_empty() {
        return Err(CryptoKeystoreError::MlsKeyStoreError(format!(
            "{} unexpected trailing bytes",
            rest.len()
        )));
    }
    Ok(value)
}

/// Convert a value into another type with the same serialization.
///
/// openmls hands us its types as generic `Serialize`/`Deserialize` parameters. Where we need to look inside one,
/// this turns it into the concrete openmls type behind it, or a plain Rust type it wraps, and back.
pub(crate) fn convert<From: Serialize + ?Sized, To: DeserializeOwned>(value: &From) -> CryptoKeystoreResult<To> {
    deser_exact(&Zeroizing::new(ser(value)?))
}

/// The raw bytes of a value that is a byte string underneath, such as a group id or a hash reference.
///
/// Nothing checks that the value really is one: this accepts anything serializable. Only pass values whose
/// serialization is a single byte string. Anything else either fails or, worse, yields bytes that happen to decode as
/// one.
pub(crate) fn raw_bytes(value: &(impl Serialize + ?Sized)) -> CryptoKeystoreResult<Vec<u8>> {
    convert(value)
}
