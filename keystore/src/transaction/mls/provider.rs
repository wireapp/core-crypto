//! openmls's `StorageProvider`, implemented on [`Storage`].
//!
//! The methods are grouped by what they store, in the order openmls's trait declares them.

use openmls::prelude::KeyPackageBundle as MlsKeyPackageBundle;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider, traits};
use zeroize::Zeroizing;

use super::{
    Storage, group_state,
    group_state_sql::{self, BlobColumn},
    storage::Access,
};
use crate::{
    CryptoKeystoreError,
    connection::{convert, deser_exact, raw_bytes},
    deser,
    entities::{
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredEpochEncryptionKeypairPkRef, StoredKeyPackage,
        StoredPskBundle,
    },
    ser,
    traits::{EntityDatabaseMutation as _, EntityDeleteBorrowed as _, EntityGetBorrowed as _},
};

impl<'a, B: Access<'a>> StorageProvider<CURRENT_VERSION> for Storage<B> {
    type Error = CryptoKeystoreError;

    //
    // Group state
    //
    // Most pieces are stored serialized. The interim transcript hash and confirmation tag are stored as raw bytes,
    // and the own leaf index and group state in typed columns; see the V53 migration.
    //

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_group_blob(group_id, BlobColumn::JoinConfig, config)
    }

    fn append_own_leaf_node<GroupId: traits::GroupId<CURRENT_VERSION>, LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        group_state_sql::append_own_leaf_node(&*self.write_conn()?, &raw_bytes(group_id)?, &ser(leaf_node)?)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        group_state_sql::queue_proposal(
            &*self.write_conn()?,
            &raw_bytes(group_id)?,
            &raw_bytes(proposal_ref)?,
            &ser(proposal)?,
        )
    }

    fn write_tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_group_blob(group_id, BlobColumn::Tree, tree)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write_group_bytes(group_id, BlobColumn::InterimTranscriptHash, interim_transcript_hash)
    }

    fn write_context<GroupId: traits::GroupId<CURRENT_VERSION>, GroupContext: traits::GroupContext<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let serialized = ser(group_context)?;
        let context = deser_exact::<openmls::group::GroupContext>(&serialized)?;
        group_state_sql::write_context(
            &*self.write_conn()?,
            &raw_bytes(group_id)?,
            &serialized,
            context.epoch().as_u64(),
            context.ciphersuite() as u16,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write_group_bytes(group_id, BlobColumn::ConfirmationTag, confirmation_tag)
    }

    fn write_group_state<GroupState: traits::GroupState<CURRENT_VERSION>, GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        let serialized = Zeroizing::new(ser(group_state)?);
        let status = group_state::status_from_serialized(&serialized)?;
        group_state_sql::write_group_status(&*self.write_conn()?, &raw_bytes(group_id)?, &status)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_blob(group_id, BlobColumn::MessageSecrets, message_secrets)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_group_blob(group_id, BlobColumn::ResumptionPskStore, resumption_psk_store)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        group_state_sql::write_own_leaf_index(
            &*self.write_conn()?,
            &raw_bytes(group_id)?,
            convert::<_, u32>(own_leaf_index)?,
        )
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_group_blob(group_id, BlobColumn::EpochSecrets, group_epoch_secrets)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::JoinConfig)
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>, LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        group_state_sql::own_leaf_nodes(&*self.read_conn()?, &raw_bytes(group_id)?)?
            .iter()
            .map(|leaf_node| deser(leaf_node))
            .collect()
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        group_state_sql::queued_proposal_refs(&*self.read_conn()?, &raw_bytes(group_id)?)?
            .iter()
            .map(|proposal_ref| convert(proposal_ref))
            .collect()
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        group_state_sql::queued_proposals(&*self.read_conn()?, &raw_bytes(group_id)?)?
            .iter()
            .map(|(proposal_ref, proposal)| Ok((convert(proposal_ref)?, deser(proposal)?)))
            .collect()
    }

    fn tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::Tree)
    }

    fn group_context<GroupId: traits::GroupId<CURRENT_VERSION>, GroupContext: traits::GroupContext<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::Context)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read_group_bytes(group_id, BlobColumn::InterimTranscriptHash)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read_group_bytes(group_id, BlobColumn::ConfirmationTag)
    }

    fn group_state<GroupState: traits::GroupState<CURRENT_VERSION>, GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        let Some(status) = group_state_sql::read_group_status(&*self.read_conn()?, &raw_bytes(group_id)?)? else {
            return Ok(None);
        };
        let serialized = group_state::serialized_from_status(status);
        deser_exact(&serialized).map(Some)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::MessageSecrets)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::ResumptionPskStore)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        group_state_sql::read_own_leaf_index(&*self.read_conn()?, &raw_bytes(group_id)?)?
            .map(|own_leaf_index| convert(&own_leaf_index))
            .transpose()
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_group_blob(group_id, BlobColumn::EpochSecrets)
    }

    fn remove_proposal<GroupId: traits::GroupId<CURRENT_VERSION>, ProposalRef: traits::ProposalRef<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        group_state_sql::remove_proposal(&*self.write_conn()?, &raw_bytes(group_id)?, &raw_bytes(proposal_ref)?)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        group_state_sql::delete_own_leaf_nodes(&*self.write_conn()?, &raw_bytes(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::JoinConfig)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(&self, group_id: &GroupId) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::Tree)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::ConfirmationTag)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        group_state_sql::clear_group_status(&*self.write_conn()?, &raw_bytes(group_id)?)
    }

    /// Delete the context, but not the `epoch` and `ciphersuite` columns derived from it.
    ///
    /// Those can't be NULL. They go when core-crypto deletes the group's row.
    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(&self, group_id: &GroupId) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::Context)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::InterimTranscriptHash)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::MessageSecrets)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::ResumptionPskStore)
    }

    /// Does nothing.
    ///
    /// The own leaf index is a column of the group's row that can't be NULL. It goes when core-crypto deletes the
    /// row. openmls only loads a group when every piece of its state is present, so a leftover index doesn't bring
    /// a deleted group back.
    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.clear_group_blob(group_id, BlobColumn::EpochSecrets)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        group_state_sql::clear_proposal_queue(&*self.write_conn()?, &raw_bytes(group_id)?)
    }

    //
    // Signature keys
    //
    // We store signature keys with their credentials, through the keystore's own API. openmls never touches them
    // itself.
    //

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
        _signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        Err(CryptoKeystoreError::IncorrectApiUsage(
            "signature keys are stored with their credential, through the keystore API",
        ))
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        Err(CryptoKeystoreError::IncorrectApiUsage(
            "signature keys are loaded with their credential, through the keystore API",
        ))
    }

    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>>(
        &self,
        _public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        Err(CryptoKeystoreError::IncorrectApiUsage(
            "signature keys are deleted with their credential, through the keystore API",
        ))
    }

    //
    // Encryption key pairs, keyed by the raw public key
    //

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        StoredEncryptionKeyPair {
            pk: raw_bytes(public_key)?,
            sk: ser(key_pair)?,
        }
        .save(&self.transaction()?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        let public_key = raw_bytes(public_key)?;
        let conn = self.read_conn()?;
        StoredEncryptionKeyPair::get_borrowed(&conn, &public_key)?
            .map(|stored| deser(&stored.sk))
            .transpose()
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        StoredEncryptionKeyPair::delete_borrowed(&self.transaction()?, &raw_bytes(public_key)?)?;
        Ok(())
    }

    //
    // Encryption key pairs of past epochs, keyed by group, epoch and our leaf index
    //

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        StoredEpochEncryptionKeypair {
            conversation_id: raw_bytes(group_id)?.as_slice().into(),
            own_leaf_idx: leaf_index,
            epoch: convert::<_, u64>(epoch)?,
            keypairs: ser(key_pairs)?,
        }
        .save(&self.transaction()?)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let group_id = raw_bytes(group_id)?;
        let key = StoredEpochEncryptionKeypairPkRef::new(&group_id, leaf_index, convert::<_, u64>(epoch)?);
        let conn = self.read_conn()?;
        match StoredEpochEncryptionKeypair::get_borrowed(&conn, key)? {
            Some(stored) => deser(&stored.keypairs),
            None => Ok(Vec::new()),
        }
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let group_id = raw_bytes(group_id)?;
        let key = StoredEpochEncryptionKeypairPkRef::new(&group_id, leaf_index, convert::<_, u64>(epoch)?);
        StoredEpochEncryptionKeypair::delete_borrowed(&self.transaction()?, key)?;
        Ok(())
    }

    //
    // Key packages, keyed by the raw hash reference
    //

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackageBundle: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackageBundle,
    ) -> Result<(), Self::Error> {
        let key_package_ref = raw_bytes(hash_ref)?;
        // openmls only ever stores its own `KeyPackageBundle` here.
        let bundle = convert::<_, MlsKeyPackageBundle>(key_package)?;

        StoredKeyPackage::from_key_package(
            key_package_ref.clone(),
            ser(bundle.key_package())?,
            bundle.key_package(),
        )?
        .save(&self.transaction()?)?;
        StoredKeyPackage::save_private_keys(
            &self.transaction()?,
            &key_package_ref,
            &Zeroizing::new(ser(bundle.init_private_key())?),
            &Zeroizing::new(ser(bundle.encryption_private_key())?),
        )
    }

    fn key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackageBundle: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
    ) -> Result<Option<KeyPackageBundle>, Self::Error> {
        let key_package_ref = raw_bytes(hash_ref)?;
        let conn = self.read_conn()?;
        let Some(stored) = StoredKeyPackage::load_with_private_keys(&conn, &key_package_ref)? else {
            return Ok(None);
        };
        let bundle = MlsKeyPackageBundle::new(
            deser_exact(&stored.key_package)?,
            deser_exact(&stored.hpke_init_private_key)?,
            deser_exact(&stored.leaf_encryption_private_key)?,
        );
        convert(&bundle).map(Some)
    }

    fn delete_key_package<HashReference: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &HashReference,
    ) -> Result<(), Self::Error> {
        StoredKeyPackage::delete_borrowed(&self.transaction()?, &raw_bytes(hash_ref)?)?;
        Ok(())
    }

    //
    // Pre-shared keys
    //
    // The id of a PSK is a structure, not a byte string, so it's stored serialized.
    //

    fn write_psk<PskId: traits::PskId<CURRENT_VERSION>, PskBundle: traits::PskBundle<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        StoredPskBundle {
            psk_id: ser(psk_id)?,
            psk: ser(psk)?,
        }
        .save(&self.transaction()?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        let psk_id = ser(psk_id)?;
        let conn = self.read_conn()?;
        StoredPskBundle::get_borrowed(&conn, &psk_id)?
            .map(|stored| deser(&stored.psk))
            .transpose()
    }

    fn delete_psk<PskId: traits::PskId<CURRENT_VERSION>>(&self, psk_id: &PskId) -> Result<(), Self::Error> {
        StoredPskBundle::delete_borrowed(&self.transaction()?, &ser(psk_id)?)?;
        Ok(())
    }
}
