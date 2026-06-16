use crate::{CoreCryptoError, CoreCryptoResult};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    uniffi::Object,
    derive_more::Display,
)]
#[uniffi::export(Eq, Hash, Display)]
/// A Uuid.
// It's currently just used as a user id. However, we're calling it `Uuid`, because it might potentially be used in
// other places, too, e.g., conversation ids.
pub struct Uuid(uuid::Uuid);

#[uniffi::export]
impl Uuid {
    /// Parse a `Uuid` from a string.
    #[uniffi::constructor]
    pub fn new(uuid: &str) -> CoreCryptoResult<Self> {
        uuid::Uuid::try_parse(uuid)
            .map(Self)
            .map_err(|e| CoreCryptoError::Other {
                msg: format!("invalid uuid: {e}"),
            })
    }
}
