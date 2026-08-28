use core_crypto_keystore::{
    entities::{
        ConversationIdRef as KeystoreConversationIdRef, MessageRxCounterPkRef, StoredEpochEncryptionKeypair,
        StoredEpochEncryptionKeypairPkRef, TargetedMessageRxCounter, TntSecret, TntSecretPkRef,
    },
    traits::FetchFromDatabase as _,
};
use openmls::{
    group::{MlsGroup, group_context::GroupContext},
    prelude::{HpkePrivateKey, Member},
    treesync::EncryptionKey,
};
use openmls_traits::key_store::{MlsEntity, MlsEntityId};
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use super::{HpkeContextData, PskId, TargetedMessageContext, derive_targeted_message_psk, extract_hpke_context_data};
use crate::{
    CryptoProvider, DecryptedMessage, KeystoreError, OpenMlsError, RecursiveError, TlsCodecError,
    mls::conversation::{
        ConversationMut, Error, MlsGroupState, Result, TargetedMessagePolicy,
        config::{MAX_FUTURE_EPOCHS, MAX_PAST_EPOCHS},
        mutable::tnt::{ProtocolVersion, TargetedMessage},
    },
};

impl ConversationMut {
    pub(in crate::mls::conversation::mutable::tnt) async fn decrypt_targeted(
        &self,
        message: TargetedMessage,
        policy: TargetedMessagePolicy,
        protocol_version: ProtocolVersion,
        sender: &Member,
    ) -> Result<DecryptedMessage> {
        let mls_group = self.group().await;
        if message.recipient != mls_group.own_leaf_index() {
            return Err(Error::MlsMessageInvalidState(
                "TargetedMessage wasn't targeted to this client",
            ));
        }

        let message_epoch = message.epoch.as_u64();
        let group_epoch = mls_group.epoch().as_u64();
        let max_future_epoch = group_epoch.saturating_add(MAX_FUTURE_EPOCHS);
        if message_epoch > group_epoch && message_epoch <= max_future_epoch {
            return Err(Error::BufferedFutureMessage { message_epoch });
        } else if message_epoch > max_future_epoch {
            return Err(Error::UnbufferedFarFutureMessage);
        }

        let database = self.database().await?;
        let counter_pk = MessageRxCounterPkRef::new(self.id.as_ref().into(), message.sender().u32(), group_epoch);
        let existing_counter = database
            .get_borrowed::<TargetedMessageRxCounter>(counter_pk)
            .await
            .map_err(KeystoreError::wrap("getting TargetedMessageRxCounter"))?
            .map(|counter| counter.count)
            .unwrap_or_default();
        if u32::from(message.counter) <= existing_counter {
            return Err(Error::DuplicateMessage);
        }

        let crypto_provider = self.crypto_provider().await?;
        let cipher_suite = &self.cipher_suite();
        let (context_data, decryption_key) = self
            .load_hpke_decryption_data(&mls_group, &crypto_provider, &message, policy, protocol_version)
            .await?;
        let aad = message
            .counter
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TntMessageCounter"))?;
        let padded_plaintext = crypto_provider
            .hpke_open_psk(
                cipher_suite.hpke_config(),
                &message.payload,
                &decryption_key,
                &context_data.info,
                &aad,
                &context_data.psk,
                &context_data.psk_id,
            )
            .map_err(OpenMlsError::wrap("decrypting targeted message"))?;

        // Remove padding from plaintext: VLBytes contains a length prefix which tells the deserializer the plaintext
        // length.
        let plaintext = VLBytes::tls_deserialize(&mut padded_plaintext.as_slice())
            .map_err(TlsCodecError::deserialize("TargetedMessageContent"))?
            .into();

        let tx = self
            .tx_context
            .inner()
            .await
            .map_err(RecursiveError::transaction("getting inner context"))?;
        let tx = tx.transaction();
        tx.save(TargetedMessageRxCounter {
            conversation_id: self.id().into(),
            sender: message.sender().u32(),
            epoch: group_epoch,
            count: message.counter.into(),
        })
        .await
        .map_err(KeystoreError::wrap("persisting TargetedMessageRxCounter"))?;

        let decrypted_bytes = self.extract_sender_id(sender, plaintext).await?;

        match policy {
            TargetedMessagePolicy::Transient => Ok(DecryptedMessage::TransientTargeted(decrypted_bytes)),
            TargetedMessagePolicy::Persisted => Ok(DecryptedMessage::PersistedTargeted(decrypted_bytes)),
        }
    }

    /// Get the HPKE context and private key from the live group state or load it from the database if the message comes
    /// from a past epoch.
    async fn load_hpke_decryption_data(
        &self,
        mls_group: &MlsGroupState,
        crypto_provider: &CryptoProvider,
        message: &TargetedMessage,
        policy: TargetedMessagePolicy,
        protocol_version: ProtocolVersion,
    ) -> Result<(HpkeContextData, HpkePrivateKey), Error> {
        if message.epoch == mls_group.epoch() {
            let context = TargetedMessageContext::new(
                protocol_version,
                policy,
                message.sender(),
                message.recipient,
                mls_group.export_group_context().clone(),
            );
            let context_data = extract_hpke_context_data(crypto_provider, &context, mls_group)?;
            let decryption_key = self.load_decryption_key(mls_group).await?;
            return Ok((context_data, decryption_key));
        }

        let epoch_distance = mls_group.epoch().as_u64() - message.epoch.as_u64();
        if epoch_distance > MAX_PAST_EPOCHS as u64 {
            return Err(Error::MessageEpochTooOld);
        }

        let database = self.database().await?;
        let key = TntSecretPkRef::new(
            KeystoreConversationIdRef::new(mls_group.group_id().as_slice()),
            message.epoch.as_u64(),
        );
        let secret = database
            .get_borrowed::<TntSecret>(key)
            .await
            .map_err(KeystoreError::wrap("loading tnt secret"))?
            .ok_or(Error::MlsGroupInvalidState("tnt secret is missing"))?;
        let group_context = GroupContext::tls_deserialize(&mut secret.group_context.as_slice())
            .map_err(TlsCodecError::deserialize("TntSecret GroupContext"))?;
        let context = TargetedMessageContext::new_with_current_protocol_version(
            policy,
            &group_context,
            message.sender(),
            message.recipient,
        );
        let info = context
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("TargetedMessageContext"))?;
        let psk_id = PskId::new(mls_group.group_id().clone(), message.epoch)
            .tls_serialize_detached()
            .map_err(TlsCodecError::serialize("PskId"))?;
        let decryption_key = core_crypto_keystore::deser(&secret.hpke_private_key)
            .map_err(KeystoreError::wrap("deserializing tnt hpke private key"))?;
        let context_data = HpkeContextData {
            info,
            psk_id,
            psk: secret.targeted_message_psk.clone(),
        };
        Ok((context_data, decryption_key))
    }

    pub(in crate::mls::conversation) async fn create_tnt_secret(&self, mls_group: &MlsGroup) -> Result<TntSecret> {
        let crypto_provider = self.crypto_provider().await?;
        let hpke_private_key = self.load_decryption_key(mls_group).await?;
        let targeted_message_psk = derive_targeted_message_psk(&crypto_provider, mls_group)?;

        Ok(TntSecret {
            conversation_id: mls_group.group_id().as_slice().into(),
            epoch: mls_group.epoch().as_u64(),
            hpke_private_key: core_crypto_keystore::ser(&hpke_private_key)
                .map_err(KeystoreError::wrap("serializing tnt hpke private key"))?,
            group_context: mls_group
                .export_group_context()
                .tls_serialize_detached()
                .map_err(TlsCodecError::serialize("TntSecret GroupContext"))?,
            targeted_message_psk,
        })
    }

    // Ideally, openmls would offer this API for us, but it doesn't. So we load the data we need from the database.
    async fn load_decryption_key(&self, mls_group: &MlsGroup) -> Result<HpkePrivateKey> {
        let kp_ref = StoredEpochEncryptionKeypairPkRef::new(
            mls_group.group_id().as_slice(),
            mls_group.own_leaf_index().u32(),
            mls_group.epoch().as_u64(),
        );

        let database = self.database().await?;

        let stored_keypairs = database
            .get_borrowed::<StoredEpochEncryptionKeypair>(kp_ref)
            .await
            .map_err(KeystoreError::wrap("loading epoch encryption keypairs"))?
            .ok_or(Error::MlsGroupInvalidState("epoch encryption keypairs are missing"))?;

        let keypairs = core_crypto_keystore::deser::<PersistedEpochEncryptionKeypairs>(&stored_keypairs.keypairs)
            .map_err(KeystoreError::wrap("deserializing epoch encryption key"))?;
        let own_encryption_key = mls_group
            .own_leaf_node()
            .ok_or(Error::MlsGroupInvalidState("own leaf node is missing"))?
            .encryption_key();

        keypairs
            .0
            .into_iter()
            .find(|keypair| keypair.public_key.as_slice() == own_encryption_key.as_slice())
            .map(|keypair| keypair.private_key.key)
            .ok_or(Error::MlsGroupInvalidState("own leaf encryption keypair is missing"))
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedEpochEncryptionKeypairs(Vec<PersistedEncryptionKeypair>);

impl MlsEntity for PersistedEpochEncryptionKeypairs {
    const ID: MlsEntityId = MlsEntityId::EpochEncryptionKeyPair;
}

#[derive(Serialize, Deserialize)]
struct PersistedEncryptionKeypair {
    public_key: EncryptionKey,
    private_key: PersistedEncryptionPrivateKey,
}

#[derive(Serialize, Deserialize)]
struct PersistedEncryptionPrivateKey {
    key: HpkePrivateKey,
}
