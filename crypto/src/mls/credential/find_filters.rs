use openmls::prelude::{CredentialType, SignatureScheme};

use crate::ClientId;

/// Filters to narrow down the set of credentials returned from [`Credential::find`][super::Credential::find].
///
/// Filters which are unset allow any value.
///
/// ## Example
///
/// ```no_run
/// # use crypto::src::mls::{Credential, FindFilters};
/// # use openmls::prelude::CredentialType;
/// # let database = todo!();
/// # let client_id = todo!();
/// // get all basic credentials for a client
/// let credentials = Credential::find(
///     &database,
///     FindFilters::builder()
///         .client_id(&client_id)
///         .credential_type(CredentialType::Basic)
///         .build()
/// )?;
/// # println!("{credentials:?}");
/// ```
#[derive(Debug, Default, typed_builder::TypedBuilder)]
pub struct FindFilters<'a> {
    /// Client ID to search for
    #[builder(default, setter(strip_option))]
    pub client_id: Option<&'a ClientId>,
    /// Signature scheme / ciphersuite to build for
    #[builder(default, setter(strip_option))]
    pub signature_scheme: Option<SignatureScheme>,
    /// Credential type to build for
    #[builder(default, setter(strip_option))]
    pub credential_type: Option<CredentialType>,
}
