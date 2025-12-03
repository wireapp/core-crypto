use serde::Serialize;

use crate::CryptoKeystoreResult;

/// This trait produces an encrypted form of this struct, where all sensitive fields have been
/// encrypted using the [`EncryptData`][super::EncryptData] helper.
///
/// This is quite likely to be handled automatically by a macro, depending on how annoying it is to implement everywhere.
///
/// ## Example
///
/// ```rust,ignore
/// // Foo is an Entity
/// struct Foo {
///     id: Vec<u8>,
///     sensitive_data: Vec<u8>, // sensitive!
/// }
///
/// #[derive(serde::Serialize)]
/// struct EncryptedFoo<'a> {
///     id: &'a Vec<u8>,
///     sensitive_data: Vec<u8>,
/// }
///
/// impl<'a> Encrypting<'a> for Foo {
///     type EncryptedForm: EncryptedFoo<'a>;
///
///     fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<EncryptedFoo<'a>> {
///         Ok(EncryptedFoo {
///             id: &self.id,
///             sensitive_data: self.encrypt_data(cipher, &self.sensitive_data)?,
///         })
///     }
/// }
/// ```
///
/// This can then be used like:
///
/// ```rust,ignore
/// let json = serde_json::to_string(&foo.encrypt(cipher)?)?;
/// ```
pub trait Encrypting<'a> {
    /// This type must be serializable, but can depend on the lifetime of `self` to reduce copying.
    type EncryptedForm: 'a + Serialize;

    /// Make an instance of the encrypted form of this struct, for which all sensitive fields have been encrypted.
    fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::EncryptedForm>;
}
