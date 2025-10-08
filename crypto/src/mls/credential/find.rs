use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, StoredCredential},
};
use mls_crypto_provider::Database;
use openmls::prelude::{Credential as MlsCredential, CredentialType, SignatureScheme};
use tls_codec::Deserialize as _;

use super::{Error, Result, keypairs};
use crate::{ClientId, Credential, KeystoreError, RecursiveError, mls::session::id::ClientIdRef};

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
    pub client_id: Option<&'a ClientIdRef>,
    /// Signature scheme / ciphersuite to build for
    #[builder(default, setter(strip_option))]
    pub signature_scheme: Option<SignatureScheme>,
    /// Credential type to build for
    #[builder(default, setter(strip_option))]
    pub credential_type: Option<CredentialType>,
}

impl Credential {
    /// Find all credentials in the database matching the provided filters.
    //
    // Our database does not currently support indices or even in-db searching, so this moves all data
    // from the DB to the runtime, decodes everything, and then filters. This is obviously suboptimal,
    // but that's only going to be improved with WPB-20839.
    pub async fn find(database: &Database, find_filters: FindFilters<'_>) -> Result<Vec<Self>> {
        let FindFilters {
            client_id,
            signature_scheme,
            credential_type,
        } = find_filters;

        let mut stored_keypairs = keypairs::load_all(database).await?;
        if let Some(signature_scheme) = signature_scheme {
            stored_keypairs.retain(|keypair| keypair.signature_scheme == signature_scheme as u16);
        }
        if stored_keypairs.is_empty() {
            return Ok(Vec::new());
        }
        let stored_keypairs = stored_keypairs
            .iter()
            .map(keypairs::deserialize)
            .collect::<Result<Vec<_>>>()
            .map_err(RecursiveError::mls_credential(
                "deserializing keypairs when finding credentials",
            ))?;

        let partial_credentials = database
            .find_all::<StoredCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all credentials"))?
            .into_iter()
            .filter(|stored| {
                client_id
                    .map(|client_id| client_id.as_ref() == stored.id)
                    .unwrap_or(true)
            })
            .map(|stored| -> Result<_> {
                let mls_credential = MlsCredential::tls_deserialize_exact(&stored.credential)
                    .map_err(Error::tls_deserialize("Credential"))?;
                // What a perfect example of a place where a `ClientIdRef` would be very helpful
                let client_id = ClientId::from(stored.id.to_owned());
                Ok((mls_credential, client_id, stored.created_at))
            });

        let mut out = Vec::new();
        for partial in partial_credentials {
            let (ref mls_credential, client_id, created_at) = partial?;

            if !credential_type
                .map(|credential_type| credential_type == mls_credential.credential_type())
                .unwrap_or(true)
            {
                // credential type did not match
                continue;
            }

            for signature_key_pair in &stored_keypairs {
                if Self::validate_mls_credential(mls_credential, &client_id, signature_key_pair).is_err() {
                    // this probably doesn't happen often, but no point getting weird about it if it does;
                    // just indicates it's not a match
                    continue;
                }

                out.push(Self {
                    mls_credential: mls_credential.to_owned(),
                    signature_key_pair: signature_key_pair.to_owned(),
                    created_at,
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
