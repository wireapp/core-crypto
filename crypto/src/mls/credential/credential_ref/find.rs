use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, StoredCredential},
};
use mls_crypto_provider::Database;
use openmls::prelude::{Credential as MlsCredential};
use tls_codec::Deserialize as _;

use super::{Error, Result};
use crate::{ClientId, Ciphersuite, CredentialRef, CredentialType, KeystoreError, mls::session::id::ClientIdRef};

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
    /// Public key to search for
    #[builder(default, setter(strip_option))]
    pub public_key: Option<&'a [u8]>,
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
    pub(crate) async fn find(database: &Database, find_filters: FindFilters<'_>) -> Result<Vec<Self>> {
        let FindFilters {
            client_id,
            ciphersuite,
            credential_type,
            public_key,
            earliest_validity,
        } = find_filters;

        let partial_credentials = database
            .find_all::<StoredCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all credentials"))?
            .into_iter()
            .filter(|stored| {
                client_id.is_none_or(|client_id| client_id.as_ref() == stored.id)
                    && earliest_validity.is_none_or(|earliest_validity| earliest_validity == stored.created_at)
                    && ciphersuite.is_none_or(|ciphersuite| u16::from(ciphersuite) == stored.ciphersuite)
                    && public_key.is_none_or(|public_key| public_key == stored.public_key)
            })
            .map(|stored| -> Result<_> {
                let mls_credential = MlsCredential::tls_deserialize_exact(&stored.credential)
                    .map_err(Error::tls_deserialize("Credential"))?;
                Ok((mls_credential, stored))
            });

        let mut out = Vec::new();
        for partial in partial_credentials {
            let (ref mls_credential, ref stored_credential) = partial?;

            if credential_type.is_some_and(|credential_type| credential_type != mls_credential.credential_type()) {
                // credential type did not match
                continue;
            }

            if let Ok(r#type) = mls_credential.credential_type().try_into()
                && let Ok(ciphersuite) = stored_credential.ciphersuite.try_into()
            {
                out.push(Self {
                    client_id: ClientId(stored_credential.id.clone()),
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
    pub async fn get_all(database: &Database) -> Result<Vec<Self>> {
        Self::find(database, FindFilters::default()).await
    }
}
