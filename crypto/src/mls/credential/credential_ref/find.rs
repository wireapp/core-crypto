use core_crypto_keystore::{
    connection::FetchFromDatabase as _,
    entities::{EntityFindParams, StoredCredential},
};
use mls_crypto_provider::Database;
use openmls::prelude::{Credential as MlsCredential, CredentialType, SignatureScheme};
use tls_codec::Deserialize as _;

use super::{super::keypairs, Error, Result};
use crate::{ClientId, Credential, CredentialRef, KeystoreError, RecursiveError, mls::session::id::ClientIdRef};

/// Filters to narrow down the set of credentials returned from [`CredentialRef::find`].
///
/// Filters which are unset allow any value.
///
/// ## Example
///
/// ```no_run
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
    /// Signature scheme / ciphersuite to search for
    #[builder(default, setter(strip_option))]
    pub signature_scheme: Option<SignatureScheme>,
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
            signature_scheme,
            credential_type,
            public_key,
            earliest_validity,
        } = find_filters;

        let mut stored_keypairs = keypairs::load_all(database)
            .await
            .map_err(RecursiveError::mls_credential(
                "loading all keypairs while finding credentials",
            ))?;
        if let Some(signature_scheme) = signature_scheme {
            stored_keypairs.retain(|keypair| keypair.signature_scheme == signature_scheme as u16);
        }
        if stored_keypairs.is_empty() {
            return Ok(Vec::new());
        }
        let stored_keypairs = stored_keypairs
            .iter()
            .map(|stored_keypair| {
                keypairs::deserialize(stored_keypair)
                    .map_err(RecursiveError::mls_credential(
                        "deserializing keypair while finding credentials",
                    ))
                    .map_err(Into::into)
            })
            .filter(|stored_keypair_result| {
                stored_keypair_result.as_ref().ok().is_none_or(|stored_keypair| {
                    public_key.is_none_or(|public_key| stored_keypair.public() == public_key)
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let partial_credentials = database
            .find_all::<StoredCredential>(EntityFindParams::default())
            .await
            .map_err(KeystoreError::wrap("finding all credentials"))?
            .into_iter()
            .filter(|stored| {
                client_id.is_none_or(|client_id| client_id.as_ref() == stored.id)
                    && earliest_validity.is_none_or(|earliest_validity| earliest_validity == stored.created_at)
            })
            .map(|stored| -> Result<_> {
                let mls_credential = MlsCredential::tls_deserialize_exact(&stored.credential)
                    .map_err(Error::tls_deserialize("Credential"))?;
                Ok((mls_credential, stored))
            });

        let mut out = Vec::new();
        for partial in partial_credentials {
            let (ref mls_credential, ref stored_credential) = partial?;

            if !credential_type
                .map(|credential_type| credential_type == mls_credential.credential_type())
                .unwrap_or(true)
            {
                // credential type did not match
                continue;
            }

            for signature_key_pair in &stored_keypairs {
                if Credential::validate_mls_credential(
                    mls_credential,
                    <&ClientIdRef>::from(&stored_credential.id),
                    signature_key_pair,
                )
                .is_err()
                {
                    // this probably doesn't happen often, but no point getting weird about it if it does;
                    // just indicates it's not a match
                    continue;
                }

                out.push(Self {
                    client_id: ClientId(stored_credential.id.clone()),
                    r#type: mls_credential.credential_type(),
                    signature_scheme: signature_key_pair.signature_scheme(),
                    earliest_validity: stored_credential.created_at,
                    public_key: signature_key_pair.public().to_owned(),
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
