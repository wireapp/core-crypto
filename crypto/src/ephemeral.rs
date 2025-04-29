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
use openmls::prelude::{Credential, KeyPackage, SignatureScheme};

use crate::{
    CoreCrypto, MlsError, RecursiveError, Result,
    mls::{HasSessionAndCrypto as _, conversation::Conversation as _},
    prelude::{ClientId, ClientIdentifier, ConversationId},
};

/// A `HistorySecret` encodes sufficient client state that it can be used to instantiate an
/// ephemeral client.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct HistorySecret {
    client_id: Vec<u8>,
    credential: Credential,
    key_package: KeyPackage,
}

impl CoreCrypto {
    /// Generate a new [`HistorySecret`].
    ///
    /// This is useful when it's this client's turn to generate a new history client.
    ///
    /// The generated secret is cryptographically unrelated to the current CoreCrypto client.
    pub async fn generate_history_secret(&self, conversation_id: &ConversationId) -> Result<HistorySecret> {
        // generate a new completely arbitrary client id
        let client_id = uuid::Uuid::new_v4();
        let client_id = format!("history-client-{client_id}");
        let client_id = ClientId::from(client_id.into_bytes());

        // generate a transient in-memory provider with which to generate the rest of the credentials
        let provider = MlsCryptoProvider::try_new_in_memory(&DatabaseKey::generate())
            .await
            .map_err(MlsError::wrap("generating transient mls provider"))?;

        // we only care about the one ciphersuite in use for this conversation
        let conversation = self
            .get_raw_conversation(conversation_id)
            .await
            .map_err(RecursiveError::mls_client("getting raw conversation"))?;
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
        let session = self.session().await.map_err(RecursiveError::mls("getting session"))?;
        let key_package = session
            .generate_one_keypackage_from_credential_bundle(&provider, ciphersuite, &credential_bundle)
            .await
            .map_err(RecursiveError::mls_client("generating key package"))?;

        Ok(HistorySecret {
            client_id: client_id.0,
            credential: credential_bundle.credential,
            key_package,
        })
    }
}
