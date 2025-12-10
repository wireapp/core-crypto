use serde::Deserialize;

use crate::{CryptoKeystoreResult, traits::Entity};

/// This trait restores to a plaintext form of this struct, where all sensitive fields have been
/// decrypted.
///
/// This is quite likely to be handled automatically by a macro, depending on how annoying it is to implement
/// everywhere.
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
/// #[derive(serde::Deserialize)]
/// struct EncryptedFoo<'a> {
///     id: Vec<u8>,
///     sensitive_data: &'a [u8],
/// }
///
/// impl<'a> Decrypting<'a> for EncryptedFoo<'a> {
///     type DecryptedForm = Foo;
///
///     fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Foo> {
///         let id = self.id;
///         let sensitive_data = Foo::decrypt_data(cipher, &id, self.sensitive_data)?;
///         Ok(Foo {
///             id,
///             sensitive_data,
///         })
///     }
/// }
/// ```
///
/// This can then be used like:
///
/// ```rust,ignore
/// let foo = serde_json::from_str::<EncryptedFoo>(json)?.decrypt(cipher)?;
/// ```
pub trait Decrypting<'a>: 'a + Deserialize<'a> {
    type DecryptedForm: Entity;

    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::DecryptedForm>;
}

/// Helper trait for restoring from an encrypted form of this struct.
///
/// This is mainly useful so that the encrypted form does not need to be named, or even nameable.
///
/// This is quite likely to be handled automatically by a macro, depending on how annoying it is to implement
/// everywhere.
///
/// ## Example
///
/// Extending the example from [`Decrypting`]:
///
/// ```rust,ignore
/// // Foo is an Entity
/// struct Foo { ... }
///
/// #[derive(serde::Serialize)]
/// struct EncryptedFoo<'de> { ... }
///
/// impl<'de> Decrypting<'de> for EncryptedFoo<'de> {
///     type DecryptedForm = Foo;
///     fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Foo> { ... }
/// }
///
/// impl<'de> Decryptable<'de> for Foo {
///     type DecryptableFrom = EncryptedFoo<'de>;
/// }
/// ```
///
/// `EncryptedFoo` now no longer needs to appear in external code:
///
/// ```rust,ignore
/// let foo = serde_json::from_str::<Foo::DecryptableFrom>(json)?.decrypt(cipher)?;
/// ```
pub trait Decryptable<'a>: Entity {
    type DecryptableFrom: 'a + Decrypting<'a, DecryptedForm = Self>;
}
