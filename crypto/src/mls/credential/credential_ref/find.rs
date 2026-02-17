use core_crypto_keystore::{
    Sha256Hash,
    entities::{CredentialFindFilters as KeystoreFindFilters, StoredCredential},
    traits::FetchFromDatabase,
};
use openmls::prelude::Credential as MlsCredential;
use tls_codec::Deserialize as _;

use super::{Error, Result};
use crate::{Ciphersuite, ClientId, CredentialRef, CredentialType, KeystoreError, mls::session::id::ClientIdRef};

/// Filters to narrow down the set of credentials returned from various credential-finding methods.
///
/// Filters which are unset allow any value.
///
/// ## Example
///
/// ```ignore
/// # use core_crypto::{CredentialRef, CredentialFindFilters, ClientIdRef};
/// # use openmls::prelude::CredentialType;
/// # let database = todo!();
/// # let client_id = ClientIdRef::new(&[]);
/// # smol::block_on(async {
/// // get all basic credentials for a client
/// let credentials = CredentialRef::find(
///     &database,
///     CredentialFindFilters::builder()
///         .client_id(&client_id)
///         .credential_type(CredentialType::Basic)
///         .build()
/// ).await.unwrap();
/// # println!("{credentials:?}");
/// # });
/// ```
#[derive(Debug, Default, typed_builder::TypedBuilder)]
pub struct FindFilters<'a> {
    /// Client ID to search for
    #[builder(default, setter(strip_option))]
    pub client_id: Option<&'a ClientIdRef>,
    /// SHA256 hash of a public key to search for
    #[builder(default, setter(strip_option))]
    pub public_key_hash: Option<Sha256Hash>,
    /// Ciphersuite to search for
    #[builder(default, setter(strip_option))]
    pub ciphersuite: Option<Ciphersuite>,
    /// Credential type to search for
    #[builder(default, setter(strip_option))]
    pub credential_type: Option<CredentialType>,
    /// unix timestamp (seconds) of point of earliest validity to search for
    #[builder(default, setter(strip_option))]
    pub earliest_validity: Option<u64>,
}

impl CredentialRef {
    /// Find all credentials in the database matching the provided filters.
    //
    // Our database does not currently support indices or even in-db searching, so this moves all data
    // from the DB to the runtime, decodes everything, and then filters. This is obviously suboptimal,
    // but that's only going to be improved with WPB-20839.
    pub(crate) async fn find(database: &impl FetchFromDatabase, find_filters: FindFilters<'_>) -> Result<Vec<Self>> {
        let FindFilters {
            client_id,
            ciphersuite,
            credential_type,
            public_key_hash,
            earliest_validity,
        } = find_filters;

        let partial_credentials = database
            .search::<StoredCredential, _>(&KeystoreFindFilters {
                hash: public_key_hash,
                earliest_validity,
                session_id: client_id.map(AsRef::as_ref),
                ciphersuite: ciphersuite.map(Into::into),
                ..Default::default()
            })
            .await
            .map_err(KeystoreError::wrap("searching for credentials"))?
            .into_iter()
            .map(|stored| {
                MlsCredential::tls_deserialize_exact(&stored.credential)
                    .map_err(Error::tls_deserialize("Credential"))
                    .map(|mls_credential| (mls_credential, stored))
            })
            .filter(|maybe_credential| {
                maybe_credential.as_ref().ok().is_none_or(|(mls_credential, _)| {
                    credential_type.is_none_or(|credential_type| credential_type == mls_credential.credential_type())
                })
            });

        let mut out = Vec::new();
        for partial in partial_credentials {
            let (ref mls_credential, ref stored_credential) = partial?;

            if let Ok(r#type) = mls_credential.credential_type().try_into()
                && let Ok(ciphersuite) = stored_credential.ciphersuite.try_into()
            {
                out.push(Self {
                    client_id: ClientId(stored_credential.session_id.clone()),
                    r#type,
                    ciphersuite,
                    earliest_validity: stored_credential.created_at,
                    public_key: stored_credential.public_key.to_owned(),
                })
            }
        }

        Ok(out)
    }

    /// Load all credentials from the database
    pub async fn get_all(database: &impl FetchFromDatabase) -> Result<Vec<Self>> {
        Self::find(database, FindFilters::default()).await
    }
}
