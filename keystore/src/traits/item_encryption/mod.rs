//! Extension traits for encrypting entities at the item level.
//!
//! In general, the item-level encryption process works like this:
//!
//! 1. An entity desiring item-level encryption should have a parallel struct, i.e. `Foo` should have `EncryptedFoo`.
//!    The `EncryptedFoo` should have all the same fields as `Foo`, but all secure fields are represented as byte
//!    vectors.
//! 2. `EncryptedFoo` must implement [`serde::Serialize`]. Deriving it is acceptable.
//! 3. `Foo` must implement [`Encrypting<EncryptedForm = EncryptedFoo>`]. This copies all non-sensitive fields, and
//!    encrypts all sensitive fields using the [`EncryptData`] helper.
//! 4. At the point where it needs to be serialized, it produces its encryped form using [`Encrypting::encrypt`], and
//!    then passes the encrypted form to the appropriate serializer.
//!
//! Item-level decryption is similar:
//!
//! 1. An entity desiring item-level decryption should have a parallel struct, i.e. `Foo` should have an `EncryptedFoo`.
//!    The `EncryptedFoo` should have all the same fields as `Foo`, but all secure fields are represented as byte
//!    slices.
//! 2. `EncryptedFoo` must implement [`serde::Deserialize`]. Deriving it is acceptable.
//! 3. `EncryptedFoo` must implement [`Decrypting<DecryptedForm = Foo>`]. This moves all non-sensitive fields, and
//!    decrypts all sensitive fields using the [`DecryptData`] helper.
//! 4. At the point where some data needs to be deserialized and decrypted, the decryped form is deserialized (note:
//!    [`Decryptable::DecryptableFrom`]), and then [`Decrypting::decrypt`] is called to decrypt it.
//!
//! ## Associated Forms
//!
//! Sharp-eyed readers will note that [`Encrypting::EncryptedForm`] and [`Decrypting::DecryptedForm`] are not the same,
//! structurally, in their examples. This is not an accident: those two traits have different requirements in terms of
//! minimizing data-cloning. There are two strategies which can be used to deal with this:
//!
//! 1. Define a single struct where everything is owned and clone everything every time. This is probably what human
//!    implementers will do most of the time.
//! 2. Emit two different associated structs, one for each trait, and only clone where strictly necessary. This is
//!    probably what the macro will do once we get around to implementing it.

mod aad;
mod decrypt_data;
mod decrypting;
mod encrypt_data;
mod encrypting;

pub use decrypt_data::{DecryptData, DecryptWithExplicitEncryptionKey};
pub use decrypting::{Decryptable, Decrypting};
pub use encrypt_data::{EncryptData, EncryptWithExplicitEncryptionKey, EncryptionKey};
pub use encrypting::Encrypting;
