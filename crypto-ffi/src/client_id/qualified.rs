/// This type wraps `ClientId` and verifies upon instantiation that it conforms to the `<userid>-<device-id>@<domain>`
/// format.
/// Instantiate via [ClientId::parse_qualified].
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::Deref,
    derive_more::DerefMut,
    uniffi::Object,
)]
#[uniffi::export(Eq, Hash)]
pub struct QualifiedClientId(core_crypto::QualifiedClientId);
