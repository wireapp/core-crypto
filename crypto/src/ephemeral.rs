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

use mls_crypto_provider::DatabaseKey;
use openmls::prelude::{KeyPackageSecretEncapsulation, SignatureScheme};

use crate::{
    CoreCrypto, Error, MlsError, RecursiveError, Result,
    mls::credential::CredentialBundle,
    prelude::{ClientId, ClientIdentifier, MlsCiphersuite, MlsClientConfiguration, MlsCredentialType, Session},
};

/// We always instantiate history clients with this prefix in their client id, so
/// we can use prefix testing to determine with some accuracy whether or not something is a history client.
const HISTORY_CLIENT_ID_PREFIX: &str = "history-client";

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistorySecret {
    pub(crate) client_id: ClientId,
    pub(crate) credential_bundle: CredentialBundle,
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
    let identifier = ClientIdentifier::Basic(client_id);

    let cc = in_memory_cc_with_ciphersuite(ciphersuite).await?;
    let tx = cc
        .new_transaction()
        .await
        .map_err(RecursiveError::transaction("creating new transaction"))?;
    cc.init(identifier.clone(), &[ciphersuite], &cc.crypto_provider, 0)
        .await
        .map_err(RecursiveError::mls_client("initializing ephemeral cc"))?;

    // we can get a credential bundle from a provider and ciphersuite
    let mut signature_schemes = HashSet::with_capacity(1);
    signature_schemes.insert(SignatureScheme::from(ciphersuite.0));
    let bundles = identifier
        .generate_credential_bundles(&cc.crypto_provider, signature_schemes)
        .map_err(RecursiveError::mls_client("generating credential bundles"))?;
    let [(_signature_scheme, client_id, credential_bundle)] = bundles
        .try_into()
        .expect("given exactly 1 signature scheme we must get exactly 1 credential bundle");

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
    use wasm_bindgen_test::wasm_bindgen_test;

    use crate::test_utils::{SessionContext, TestContext, all_cred_cipher};

    use super::*;

    /// Create a history secret, and restore it into a CoreCrypto instance
    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn can_create_ephemeral_client(case: TestContext) {
        if case.credential_type != MlsCredentialType::Basic {
            // history client will only ever have basic credentials, so not much point in testing
            // how it interacts with an x509-only conversation
            return;
        }

        use crate::mls::conversation::Conversation as _;

        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;

        let conversation_guard = conversation.guard().await;
        let history_secret = conversation_guard.generate_history_secret().await.unwrap();

        // the history secret has to survive encoding and decoding into some arbitrary serde format,
        // so round-trip it
        // note: we're not testing the serialization format
        let encoded = rmp_serde::to_vec(&history_secret).unwrap();
        let history_secret = rmp_serde::from_slice::<HistorySecret>(&encoded).unwrap();

        let ephemeral_client = CoreCrypto::history_client(history_secret).await.unwrap();

        // so how can we test that this has actually worked, given that we have not yet implemented the
        // bit where we can actually enable history for a conversation, adding a history client? Well,
        // with the caveat that
        // WE SHOULD NOT DO THIS OUTSIDE A TESTING CONTEXT
        // , we may as well try to
        // roundtrip a conversation with Alice; that should at least prove that the ephemeral client
        // has the basic minimal set of data in its keystore set properly.
        let ephemeral_identifier = ClientIdentifier::Basic(ephemeral_client.mls.id().await.unwrap());
        let ephemeral_session_context = SessionContext::new_with_identifier(&case, ephemeral_identifier, None)
            .await
            .unwrap();

        let conversation = conversation.invite([&ephemeral_session_context]).await;

        assert!(
            conversation
                .is_functional_with([&alice, &ephemeral_session_context])
                .await
        );
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn ephemeral_client_can_receive_messages_from_x509(case: TestContext) {
        if case.credential_type != MlsCredentialType::Basic {
            // history client will only ever have basic credentials, so not much point in testing
            // how it interacts with an x509-only conversation
            return;
        }

        use crate::mls::conversation::Conversation as _;

        // set up alice with x509
        let [alice] = case.sessions_x509().await;
        let conversation = case.create_conversation([&alice]).await;

        // set up a history client for this conversation
        let conversation_guard = conversation.guard().await;
        let history_secret = conversation_guard.generate_history_secret().await.unwrap();
        let ephemeral_client = CoreCrypto::history_client(history_secret).await.unwrap();

        let ephemeral_identifier = ClientIdentifier::Basic(ephemeral_client.mls.id().await.unwrap());
        let ephemeral_session_context = SessionContext::new_with_identifier(&case, ephemeral_identifier, None)
            .await
            .unwrap();

        // can the history client decrypt messages from alice? let's find out
        let conversation = conversation.invite([&ephemeral_session_context]).await;

        assert!(
            conversation
                .is_functional_with([&alice, &ephemeral_session_context])
                .await
        );
    }
}
