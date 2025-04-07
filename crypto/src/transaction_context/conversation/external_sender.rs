//! This module is concerned with setting the external sender.

use super::{Result, TransactionContext};
use crate::{RecursiveError, prelude::MlsConversationConfiguration};

impl TransactionContext {
    /// Parses supplied key from Delivery Service in order to build back an [ExternalSender]
    pub async fn set_raw_external_senders(
        &self,
        cfg: &mut MlsConversationConfiguration,
        external_senders: Vec<Vec<u8>>,
    ) -> Result<()> {
        let mls_provider = self.mls_provider().await?;
        cfg.external_senders = external_senders
            .into_iter()
            .map(|key| {
                MlsConversationConfiguration::parse_external_sender(&key).or_else(|_| {
                    MlsConversationConfiguration::legacy_external_sender(
                        key,
                        cfg.ciphersuite.signature_algorithm(),
                        &mls_provider,
                    )
                })
            })
            .collect::<crate::mls::conversation::Result<_>>()
            .map_err(RecursiveError::mls_conversation("setting external sender"))?;
        Ok(())
    }
}
