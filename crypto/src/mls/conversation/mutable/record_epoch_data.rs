use core_crypto_keystore::{
    ancillary::ConversationEpochsNewerThan,
    entities::{
        OldEpochData, OldEpochDataPkRef, OldEpochMemberData, TargetedMessageRxCounter, TransientMessageRxCounter,
    },
    traits::{DeletableBySearchKey as _, EntityDatabaseMutation as _, FetchFromDatabase as _},
};
use openmls::group::MlsGroup;
use tls_codec::Serialize as _;

use super::{ConversationMut, Result};
use crate::{KeystoreError, RecursiveError, TlsCodecError};

impl ConversationMut {
    /// Record initial epoch data, clearing any existing epoch data which may remain from forks.
    pub(crate) async fn record_initial_epoch_data(&self) -> Result<()> {
        let tx = self.tx_context.inner().map_err(RecursiveError::context(
            "getting conversation's tx context for idempotence check for recording epoch data",
        ))?;
        let tx = tx.transaction();

        // implicit in being initial is that any equal or subsequent group state is from a fork or something
        // and must be removed.
        let newer_than = ConversationEpochsNewerThan::new(self.id().keystore(), self.epoch().await);
        OldEpochData::delete_all_matching(tx, &newer_than).map_err(KeystoreError::wrap(
            "deleting any stale epoch data on recording initial epoch data",
        ))?;

        // We also have to clean up the counters, for consistency
        TargetedMessageRxCounter::delete_all_matching(tx, &newer_than).map_err(KeystoreError::wrap(
            "deleting targeted msg rx counter on recording initial epoch data",
        ))?;
        TransientMessageRxCounter::delete_all_matching(tx, &newer_than).map_err(KeystoreError::wrap(
            "deleting transient msg rx counter on recording initial epoch data",
        ))?;

        let group_state = self.group().await;
        self.record_epoch_data(group_state.mls_group())
            .await
            .map_err(RecursiveError::context(
                "recording epoch data for new conversation creation",
            ))?;

        Ok(())
    }

    /// Idempotently record per-epoch durable data for TNT messages.
    pub(crate) async fn record_epoch_data(&self, group: &MlsGroup) -> Result<()> {
        let tx = self.tx_context.inner().map_err(RecursiveError::context(
            "getting conversation's tx context for idempotence check for recording epoch data",
        ))?;
        let tx = tx.transaction();

        let old_epoch_data_key = OldEpochDataPkRef::new(self.id.keystore(), group.epoch().as_u64());
        if tx
            .get_borrowed::<OldEpochData>(old_epoch_data_key)
            .await
            .map_err(KeystoreError::wrap("finding old epoch data for current epoch"))?
            .is_some()
        {
            return Ok(());
        }

        let tx = self.tx_context.inner().map_err(RecursiveError::context(
            "getting conversation's tx context for recording epoch data",
        ))?;
        let tx = tx.transaction();
        self.create_old_epoch_data(group)
            .await
            .map_err(RecursiveError::context("creating tnt secret for per-epoch persistence"))?
            .save(tx)
            .map_err(KeystoreError::wrap("persisting old epoch data for current epoch"))?;
        for member in group.members() {
            let credential = member
                .credential
                .tls_serialize_detached()
                .map_err(TlsCodecError::serialize("member credential"))?;
            OldEpochMemberData {
                conversation_id: self.id().keystore().into(),
                epoch: group.epoch().as_u64(),
                leaf_node_index: member.index.u32(),
                signature_key: member.signature_key,
                credential,
            }
            .save(tx)
            .map_err(KeystoreError::wrap(
                "persisting old epoch member data for current epoch",
            ))?;
        }
        Ok(())
    }
}
