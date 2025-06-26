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
//! Though ephemeral clients are full instances of `CoreCrypto` and contain the same API, they cannot
//! be used to generate messages for sending, as they don't posess a credential with a signature key:
//! Any attempt to encrypt a message will fail because the client cannot retrieve the signature key from
//! its keystore.

use mls_crypto_provider::DatabaseKey;
use openmls::prelude::KeyPackageSecretEncapsulation;

use crate::{
    CoreCrypto, Error, MlsError, RecursiveError, Result,
    prelude::{ClientId, ClientIdentifier, MlsCiphersuite, MlsClientConfiguration, MlsCredentialType, Session},
};

/// We always instantiate history clients with this prefix in their client id, so
/// we can use prefix testing to determine with some accuracy whether or not something is a history client.
pub const HISTORY_CLIENT_ID_PREFIX: &str = "history-client";

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistorySecret {
    /// Client id of the associated history client
    pub client_id: ClientId,
    pub(crate) key_package: KeyPackageSecretEncapsulation,
}

/// Create a new [`CoreCrypto`] with an **uninitialized** mls session.
///
/// You must initialize the session yourself before using this!
async fn in_memory_cc_with_ciphersuite(ciphersuite: impl Into<MlsCiphersuite>) -> Result<CoreCrypto> {
    let ciphersuites = vec![ciphersuite.into()];

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

    Ok(session.into())
}

/// Generate a new [`HistorySecret`].
///
/// This is useful when it's this client's turn to generate a new history client.
///
/// The generated secret is cryptographically unrelated to the current CoreCrypto client.
///
/// Note that this is a crate-private function; the public interface for this feature is
/// [`Conversation::generate_history_secret`][core_crypto::mls::conversation::Conversation::generate_history_secret].
/// This implementation lives here instead of there for organizational reasons.
pub(crate) async fn generate_history_secret(ciphersuite: MlsCiphersuite) -> Result<HistorySecret> {
    // generate a new completely arbitrary client id
    let client_id = uuid::Uuid::new_v4();
    let client_id = format!("{HISTORY_CLIENT_ID_PREFIX}-{client_id}");
    let client_id = ClientId::from(client_id.into_bytes());
    let identifier = ClientIdentifier::Basic(client_id.clone());

    let cc = in_memory_cc_with_ciphersuite(ciphersuite).await?;
    let tx = cc
        .new_transaction()
        .await
        .map_err(RecursiveError::transaction("creating new transaction"))?;
    cc.init(identifier, &[ciphersuite], &cc.crypto_provider, 0)
        .await
        .map_err(RecursiveError::mls_client("initializing ephemeral cc"))?;

    // we can generate a key package from the ephemeral cc and ciphersutite
    let [key_package] = tx
        .get_or_create_client_keypackages(ciphersuite, MlsCredentialType::Basic, 1)
        .await
        .map_err(RecursiveError::transaction("generating keypackages"))?
        .try_into()
        .expect("generating 1 keypackage returns 1 keypackage");
    let key_package = KeyPackageSecretEncapsulation::load(&cc.crypto_provider, key_package)
        .await
        .map_err(MlsError::wrap("encapsulating key package"))?;

    // we don't need to finish the transaction here--the point of the ephemeral CC was that no mutations would be saved there

    Ok(HistorySecret { client_id, key_package })
}

pub(crate) fn is_history_client(client_id: &ClientId) -> bool {
    client_id.starts_with(HISTORY_CLIENT_ID_PREFIX.as_bytes())
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

        let session = in_memory_cc_with_ciphersuite(history_secret.key_package.ciphersuite()).await?;
        let tx = session
            .new_transaction()
            .await
            .map_err(RecursiveError::transaction("creating new transaction"))?;

        session
            .restore_from_history_secret(history_secret)
            .await
            .map_err(RecursiveError::mls_client(
                "restoring ephemeral session from history secret",
            ))?;

        tx.finish()
            .await
            .map_err(RecursiveError::transaction("finishing transaction"))?;

        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rstest_reuse::apply;

    use crate::test_utils::{TestContext, all_cred_cipher};

    /// Create a history secret, and restore it into a CoreCrypto instance
    #[apply(all_cred_cipher)]
    async fn can_create_ephemeral_client(case: TestContext) {
        let [alice] = case.sessions().await;
        let conversation = case
            .create_conversation([&alice])
            .await
            .enable_history_sharing_notify()
            .await;

        assert_eq!(
            conversation.member_count().await,
            2,
            "the convesation should now magically have a second member"
        );

        let ephemeral_client = conversation.members().nth(1).unwrap();
        assert!(
            conversation.can_one_way_communicate(&alice, ephemeral_client).await,
            "alice can send messages to the history client"
        );
        assert!(
            !conversation.can_one_way_communicate(ephemeral_client, &alice).await,
            "the history client cannot send messages"
        );
    }
}
