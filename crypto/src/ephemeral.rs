//! Utilities for ephemeral CoreCrypto instances.
//!
//! Ephemeral instances are intended to support history sharing. History sharing works like this:
//! every history-enabled conversation has a passive "history client" as a member. This client
//! is a member of the MLS group (and can therefore decrypt messages), but it is not actively running
//! on any device or decrypting any messages.
//!
//! Approximately once daily, and whenever a member is removed from the group, a new history-sharing era
//! begins. The client submitting the commit which instantiates the new history-sharing era is responsible
//! for ensuring that the old history client is removed from the group, and new one is added. Additionally,
//! one of the first application messages in the new history-sharing era contains the serialized history
//! secret.
//!
//! When a new client joins the history-enabled conversation, they receive a list of history secrets
//! and their associated history-sharing eras (identified by the epoch number at which they start).
//! For each history-sharing era, they can instantiate an ephemeral client from the history secret,
//! and use that client to decrypt all messages in this era.
//!
//! Though ephemeral clients are full instances of `CoreCrypto` and contain the same API, they should
//! not be used to generate messages for sending. They should also not be instantiated to follow along with
//! new messages as they are received, as that's pointless; the individual credentials suffice.

use std::collections::HashSet;

use mls_crypto_provider::{DatabaseKey, MlsCryptoProvider};
use openmls::prelude::{KeyPackageSecretEncapsulation, SignatureScheme};

use crate::{
    CoreCrypto, Error, MlsError, RecursiveError, Result,
    mls::{conversation::Conversation, credential::CredentialBundle},
    prelude::{ClientId, ClientIdentifier, MlsClientConfiguration, Session},
};

/// We always instantiate history clients with this prefix in their client id, so
/// we can use prefix testing to determine with some accuracy whether or not something is a history client.
const HISTORY_CLIENT_ID_PREFIX: &str = "history-client";

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistorySecret {
    pub(crate) client_id: ClientId,
    #[serde(with = "credential_bundle_serialization_shim")]
    pub(crate) credential_bundle: CredentialBundle,
    pub(crate) key_package: KeyPackageSecretEncapsulation,
}

mod credential_bundle_serialization_shim {
    //! For Reasons, OpenMLS never implemented serialization on a credential bundle.
    //!
    //! Presumably they did not expect to need to publish and restore private keys in the use case we want.
    //! This shim module lets Serde know

    use openmls::prelude::Credential;
    use openmls_basic_credential::SignatureKeyPair;
    use {serde::Deserialize as _, serde::Serialize as _};

    use crate::mls::credential::CredentialBundle;

    /// This struct is structurally identical to a `CredentialBundle`, but can be serialized.
    #[derive(serde::Serialize)]
    struct CredentialBundleSerializeShim<'a> {
        credential: &'a Credential,
        signature_key: &'a SignatureKeyPair,
        created_at: u64,
    }

    impl<'a> From<&'a CredentialBundle> for CredentialBundleSerializeShim<'a> {
        fn from(bundle: &'a CredentialBundle) -> Self {
            Self {
                credential: &bundle.credential,
                signature_key: &bundle.signature_key,
                created_at: bundle.created_at,
            }
        }
    }

    pub(super) fn serialize<S>(credential_bundle: &CredentialBundle, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let shim = CredentialBundleSerializeShim::from(credential_bundle);
        shim.serialize(serializer)
    }

    /// This struct is structurally identical to a `CredentialBundle`, but can be deserialized.
    #[derive(serde::Deserialize)]
    struct CredentialBundleDeserializeShim {
        credential: Credential,
        signature_key: SignatureKeyPair,
        created_at: u64,
    }

    impl From<CredentialBundleDeserializeShim> for CredentialBundle {
        fn from(shim: CredentialBundleDeserializeShim) -> Self {
            Self {
                credential: shim.credential,
                signature_key: shim.signature_key,
                created_at: shim.created_at,
            }
        }
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<CredentialBundle, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let shim = CredentialBundleDeserializeShim::deserialize(deserializer)?;
        Ok(shim.into())
    }
}

/// Generate a new [`HistorySecret`].
///
/// This is useful when it's this client's turn to generate a new history client.
///
/// The generated secret is cryptographically unrelated to the current CoreCrypto client.
///
/// Note that this is a crate-private function; the public interface for this feature is [`Conversation::generate_history_secret`].
/// This implementation lives here instead of there for organizational reasons.
pub(crate) async fn generate_history_secret<'a, Conv>(conversation: &'a Conv) -> Result<HistorySecret>
where
    Conv: Conversation<'a> + Sync + ?Sized,
{
    // generate a new completely arbitrary client id
    let client_id = uuid::Uuid::new_v4();
    let client_id = format!("{HISTORY_CLIENT_ID_PREFIX}-{client_id}");
    let client_id = ClientId::from(client_id.into_bytes());

    // generate a transient in-memory provider with which to generate the rest of the credentials
    let provider = MlsCryptoProvider::try_new_in_memory(&DatabaseKey::generate())
        .await
        .map_err(MlsError::wrap("generating transient mls provider"))?;

    // we only care about the one ciphersuite in use for this conversation
    let ciphersuite = conversation.ciphersuite().await;

    // we can get a credential bundle from a provider and ciphersuite
    let identifier = ClientIdentifier::Basic(client_id);
    let mut signature_schemes = HashSet::with_capacity(1);
    signature_schemes.insert(SignatureScheme::from(ciphersuite.0));
    let bundles = identifier
        .generate_credential_bundles(&provider, signature_schemes)
        .map_err(RecursiveError::mls_client("generating credential bundles"))?;
    let [(_signature_scheme, client_id, credential_bundle)] = bundles
        .try_into()
        .expect("given exactly 1 signature scheme we must get exactly 1 credential bundle");

    // given all the other info so far, we can generate a key package
    // it's ok to use the current session because the only data inherited here is the keypackage lifetime,
    // which is not cryptographically relevant
    let session = conversation
        .session()
        .await
        .map_err(RecursiveError::mls_conversation("getting session"))?;
    let key_package = session
        .generate_one_keypackage_from_credential_bundle(&provider, ciphersuite, &credential_bundle)
        .await
        .map_err(RecursiveError::mls_client("generating key package"))?;
    let key_package = KeyPackageSecretEncapsulation::load(&provider, key_package)
        .await
        .map_err(MlsError::wrap("encapsulating key package"))?;

    Ok(HistorySecret {
        client_id,
        credential_bundle,
        key_package,
    })
}

impl CoreCrypto {
    /// Instantiate a history client.
    ///
    /// This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
    /// Other use is a logic error.
    pub async fn history_client(history_secret: HistorySecret) -> Result<Self> {
        if !history_secret
            .client_id
            .starts_with(HISTORY_CLIENT_ID_PREFIX.as_bytes())
        {
            return Err(Error::InvalidHistorySecret("client id has invalid format"));
        }

        let ciphersuites = vec![history_secret.key_package.ciphersuite().into()];

        let configuration = MlsClientConfiguration {
            // we know what ciphersuite we want, at least
            ciphersuites: ciphersuites.clone(),
            // we have the client id from the history secret, but we don't want to use it here because
            // that kicks off the `init`, and we want to inject our secret keys into the keystore before then
            client_id: None,
            // not used in in-memory client
            store_path: String::new(),
            // important so our keys aren't memory-snooped, but its actual value is irrelevant
            database_key: DatabaseKey::generate(),
            // irrelevant for this case
            external_entropy: None,
            // don't generate any keypackages; we do not want to ever add this client to a different group
            nb_init_key_packages: Some(0),
        };

        // Construct the MLS session, but don't initialize it. The implementation when `client_id` is `None` just
        // does construction, which is what we need.
        let session = Session::try_new_in_memory(configuration)
            .await
            .map_err(RecursiveError::mls("creating ephemeral session"))?;

        session
            .restore_from_history_secret(history_secret)
            .await
            .map_err(RecursiveError::mls_client(
                "restoring ephemeral session from history secret",
            ))?;

        Ok(session.into())
    }
}
