use super::{RecursionPolicy, Result};
use crate::KeystoreError;
use crate::mls::conversation::{ConversationGuard, ConversationWithMls, Error};
use crate::obfuscate::Obfuscated;
use crate::prelude::MlsBufferedConversationDecryptMessage;
use core_crypto_keystore::connection::FetchFromDatabase;
use core_crypto_keystore::entities::{EntityFindParams, MlsPendingMessage};
use log::{error, info};
use openmls::framing::{MlsMessageIn, MlsMessageInBody};
use openmls_traits::OpenMlsCryptoProvider as _;
use tls_codec::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageRestorePolicy {
    /// Retrieve and decrypt pending messages, then clear them from the keystore.
    DecryptAndClear,
    /// Clear pending messages from the keystore without decrypting them.
    ClearOnly,
}

impl ConversationGuard {
    pub(super) async fn restore_and_clear_pending_messages(
        &mut self,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let pending_messages = self
            .restore_pending_messages(MessageRestorePolicy::DecryptAndClear)
            .await?;

        if pending_messages.is_some() {
            let conversation = self.conversation().await;
            let backend = self.mls_provider().await?;
            info!(group_id = Obfuscated::from(conversation.id()); "Clearing all buffered messages for conversation");
            backend
                .key_store()
                .remove::<MlsPendingMessage, _>(conversation.id())
                .await
                .map_err(KeystoreError::wrap("removing MlsPendingMessage from keystore"))?;
        }

        Ok(pending_messages)
    }

    #[cfg_attr(target_family = "wasm", async_recursion::async_recursion(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_recursion::async_recursion)]
    pub(crate) async fn restore_pending_messages(
        &mut self,
        policy: MessageRestorePolicy,
    ) -> Result<Option<Vec<MlsBufferedConversationDecryptMessage>>> {
        let result = async move {
            let conversation = self.conversation().await;
            let conversation_id = conversation.id();
            let backend = self.mls_provider().await?;
            let keystore = backend.keystore();
            if policy == MessageRestorePolicy::ClearOnly {
                if keystore
                    .find::<MlsPendingMessage>(conversation_id)
                    .await
                    .map_err(KeystoreError::wrap("finding mls pending message by group id"))?
                    .is_some()
                {
                    keystore
                        .remove::<MlsPendingMessage, _>(conversation_id)
                        .await
                        .map_err(KeystoreError::wrap("removing mls pending message"))?;
                }
                return Ok(None);
            }

            let mut pending_messages = keystore
                .find_all::<MlsPendingMessage>(EntityFindParams::default())
                .await
                .map_err(KeystoreError::wrap("finding all mls pending messages"))?
                .into_iter()
                .filter(|pm| pm.foreign_id == *conversation_id)
                .map(|m| -> Result<_> {
                    let msg = MlsMessageIn::tls_deserialize(&mut m.message.as_slice())
                        .map_err(Error::tls_deserialize("mls message in"))?;
                    let ct = match msg.body_as_ref() {
                        MlsMessageInBody::PublicMessage(m) => m.content_type(),
                        MlsMessageInBody::PrivateMessage(m) => m.content_type(),
                        _ => return Err(Error::InappropriateMessageBodyType),
                    };
                    Ok((ct as u8, msg))
                })
                .collect::<Result<Vec<_>>>()?;

            // We want to restore application messages first, then Proposals & finally Commits
            // luckily for us that's the exact same order as the [ContentType] enum
            pending_messages.sort_by(|(a, _), (b, _)| a.cmp(b));

            info!(group_id = Obfuscated::from(conversation_id); "Attempting to restore {} buffered messages", pending_messages.len());

            // Need to drop conversation to allow borrowing `self` again.
            drop(conversation);

            let mut decrypted_messages = Vec::with_capacity(pending_messages.len());
            for (_, m) in pending_messages {
                let decrypted = self
                    .decrypt_message_inner(m, RecursionPolicy::None)
                    .await?;
                decrypted_messages.push(decrypted.into());
            }

            let decrypted_messages = (!decrypted_messages.is_empty()).then_some(decrypted_messages);

            Ok(decrypted_messages)
        }
            .await;
        if let Err(e) = &result {
            error!(error:% = e; "Error restoring pending messages");
        }
        result
    }
}
