use crate::wasm::{lower_ciphersuites, WasmError};
use crate::{
    BufferedDecryptedMessage, Ciphersuite, CommitBundle, ConversationConfiguration, ConversationInitBundle, CoreCrypto,
    CoreCryptoError, CoreCryptoResult, CredentialType, CustomConfiguration, DecryptedMessage, FfiClientId,
    MemberAddedMessages, ProposalBundle, WasmCryptoResult, WelcomeBundle,
};
use core_crypto::mls::context::CentralContext;
use core_crypto::prelude::{
    CiphersuiteName, ClientId, ClientIdentifier, ConversationId, KeyPackageIn, KeyPackageRef,
    MlsConversationConfiguration, VerifiableGroupInfo,
};
use core_crypto::{CryptoError, CryptoResult, MlsError};
use futures_util::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use std::sync::Arc;
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
#[derive(Clone)]
pub struct CoreCryptoContext {
    pub(crate) inner: Arc<CentralContext>,
}

#[wasm_bindgen]
extern "C" {
    pub type CoreCryptoCommand;

    #[wasm_bindgen(structural, method, catch)]
    pub async fn execute(this: &CoreCryptoCommand, ctx: CoreCryptoContext) -> Result<(), JsValue>;
}

#[wasm_bindgen]
impl CoreCrypto {
    /// Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
    /// otherwise, every operation performed with the context will be discarded.
    pub async fn transaction(&self, command: CoreCryptoCommand) -> WasmCryptoResult<()> {
        let context = CoreCryptoContext {
            inner: Arc::new(self.inner.new_transaction().await),
        };

        let result = command.execute(context.clone()).await;
        if result.is_ok() {
            context.inner.finish().await?;
        }
        Ok(())
    }
}

#[wasm_bindgen]
impl CoreCryptoContext {
    /// see [core_crypto::mls::context::CentralContext::mls_init]
    pub fn mls_init(&self, client_id: FfiClientId, ciphersuites: Box<[u16]>, nb_key_package: Option<u32>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let cipher_suites = lower_ciphersuites(&ciphersuites)?;
                let nb_key_package = nb_key_package
                    .map(usize::try_from)
                    .transpose()
                    .map_err(CryptoError::from)?;
                context
                    .mls_init(
                        ClientIdentifier::Basic(client_id.clone().into()),
                        cipher_suites,
                        nb_key_package,
                    )
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [core_crypto::mls::context::CentralContext::mls_generate_keypairs]
    pub fn mls_generate_keypair(&self, ciphersuites: Box<[u16]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ciphersuites = lower_ciphersuites(&ciphersuites)?;
                let pks = context
                    .mls_generate_keypairs(ciphersuites)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let js_pks = js_sys::Array::from_iter(
                    pks.into_iter()
                        .map(|kp| js_sys::Uint8Array::from(kp.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(js_pks.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::mls::context::CentralContext::mls_init_with_client_id]
    pub fn mls_init_with_client_id(
        &self,
        client_id: FfiClientId,
        signature_public_keys: Box<[Uint8Array]>,
        ciphersuites: Box<[u16]>,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ciphersuites = lower_ciphersuites(&ciphersuites)?;
                let signature_public_keys = signature_public_keys
                    .iter()
                    .map(|c| ClientId::from(c.to_vec()))
                    .collect();

                context
                    .mls_init_with_client_id(client_id.into(), signature_public_keys, ciphersuites)
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns:: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::client_public_key]
    pub fn client_public_key(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let pk = context
                    .client_public_key(ciphersuite.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(pk.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Array<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_or_create_client_keypackages]
    pub fn client_keypackages(
        &self,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
        amount_requested: u32,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let kps = context
                    .get_or_create_client_keypackages(
                        ciphersuite.into(),
                        credential_type.into(),
                        amount_requested as usize,
                    )
                    .await?
                    .into_iter()
                    .map(|kpb| {
                        kpb.tls_serialize_detached()
                            .map_err(MlsError::from)
                            .map_err(CryptoError::from)
                            .map(Into::into)
                    })
                    .collect::<CryptoResult<Vec<Vec<u8>>>>()
                    .map_err(CoreCryptoError::from)?;

                let js_kps = js_sys::Array::from_iter(
                    kps.into_iter()
                        .map(|kp| js_sys::Uint8Array::from(kp.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(js_kps.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<usize>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::client_valid_key_packages_count]
    pub fn client_valid_keypackages_count(&self, ciphersuite: Ciphersuite, credential_type: CredentialType) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let count = context
                    .client_valid_key_packages_count(ciphersuite.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(count.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<usize>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::delete_keypackages]
    #[allow(clippy::boxed_local)]
    pub fn delete_keypackages(&self, refs: Box<[Uint8Array]>) -> Promise {
        let refs = refs
            .iter()
            .map(|r| r.to_vec())
            .map(|r| KeyPackageRef::from(r.as_slice()))
            .collect::<Vec<_>>();

        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .delete_keypackages(&refs[..])
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::new_conversation]
    pub fn create_conversation(
        &self,
        conversation_id: ConversationId,
        creator_credential_type: CredentialType,
        mut config: ConversationConfiguration,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let mut lower_cfg = MlsConversationConfiguration {
                    custom: config.custom.into(),
                    ..Default::default()
                };

                if let Some(ciphersuite) = config.ciphersuite.take() {
                    let mls_ciphersuite: CiphersuiteName = ciphersuite.into();
                    lower_cfg.ciphersuite = mls_ciphersuite.into();
                }

                context
                    .set_raw_external_senders(&mut lower_cfg, config.external_senders)
                    .await?;

                context
                    .new_conversation(&conversation_id.to_vec(), creator_credential_type.into(), lower_cfg)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u64>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::conversation_epoch]
    pub fn conversation_epoch(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    context
                        .conversation_epoch(&conversation_id)
                        .await
                        .map_err(CoreCryptoError::from)?
                        .into(),
                )
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Ciphersuite>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::conversation_ciphersuite]
    pub fn conversation_ciphersuite(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(
                    Ciphersuite::from(
                        context
                            .conversation_ciphersuite(&conversation_id)
                            .await
                            .map_err(CoreCryptoError::from)?,
                    )
                    .into(),
                )
            }
            .err_into(),
        )
    }

    /// Returns: [`bool`]
    ///
    /// see [core_crypto::mls::context::CentralContext::conversation_exists]
    pub fn conversation_exists(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                WasmCryptoResult::Ok(if context.conversation_exists(&conversation_id).await? {
                    JsValue::TRUE
                } else {
                    JsValue::FALSE
                })
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::process_raw_welcome_message]
    pub fn process_welcome_message(
        &self,
        welcome_message: Box<[u8]>,
        custom_configuration: CustomConfiguration,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let bundle = context
                    .process_raw_welcome_message(welcome_message.into(), custom_configuration.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                let bundle: WelcomeBundle = bundle.into();
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&bundle)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<MemberAddedMessages>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::add_members_to_conversation]
    pub fn add_clients_to_conversation(
        &self,
        conversation_id: ConversationId,
        key_packages: Box<[Uint8Array]>,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let key_packages = key_packages
                    .iter()
                    .map(|kp| {
                        KeyPackageIn::tls_deserialize(&mut kp.to_vec().as_slice())
                            .map_err(|e| CoreCryptoError::from(WasmError::CryptoError(CryptoError::MlsError(e.into()))))
                    })
                    .collect::<CoreCryptoResult<Vec<_>>>()?;

                let commit = context
                    .add_members_to_conversation(&conversation_id, key_packages)
                    .await?;
                let commit: MemberAddedMessages = commit.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<js_sys::Uint8Array>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::remove_members_from_conversation]
    pub fn remove_clients_from_conversation(
        &self,
        conversation_id: ConversationId,
        clients: Box<[Uint8Array]>,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let clients = clients
                    .iter()
                    .cloned()
                    .map(|c| c.to_vec().into())
                    .collect::<Vec<ClientId>>();

                let commit = context
                    .remove_members_from_conversation(&conversation_id, &clients)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::mark_conversation_as_child_of]
    pub fn mark_conversation_as_child_of(&self, child_id: Box<[u8]>, parent_id: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .mark_conversation_as_child_of(&child_id.into(), &parent_id.into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<CommitBundle>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::update_keying_material]
    pub fn update_keying_material(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let commit = context
                    .update_keying_material(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let commit: CommitBundle = commit.try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::commit_pending_proposals]
    pub fn commit_pending_proposals(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let commit: Option<CommitBundle> = context
                    .commit_pending_proposals(&conversation_id)
                    .await?
                    .map(|c| c.try_into())
                    .transpose()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&commit)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::wipe_conversation]
    pub fn wipe_conversation(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .wipe_conversation(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<DecryptedMessage>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::decrypt_message]
    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let raw_decrypted_message = context
                    .decrypt_message(&conversation_id.to_vec(), payload)
                    .await
                    .map_err(CoreCryptoError::from)?;

                let decrypted_message = DecryptedMessage::try_from(raw_decrypted_message)?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&decrypted_message)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::encrypt_message]
    pub fn encrypt_message(&self, conversation_id: ConversationId, message: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ciphertext = context
                    .encrypt_message(&conversation_id.to_vec(), message)
                    .await
                    .map(|ciphertext| Uint8Array::from(ciphertext.as_slice()))
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(ciphertext.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::new_add_proposal]
    pub fn new_add_proposal(&self, conversation_id: ConversationId, keypackage: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let kp = KeyPackageIn::tls_deserialize(&mut keypackage.as_ref())
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let proposal: ProposalBundle = context
                    .new_add_proposal(&conversation_id.to_vec(), kp.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::new_update_proposal]
    pub fn new_update_proposal(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let proposal: ProposalBundle = context
                    .new_update_proposal(&conversation_id.to_vec())
                    .await?
                    .try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::new_remove_proposal]
    pub fn new_remove_proposal(&self, conversation_id: ConversationId, client_id: FfiClientId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let proposal: ProposalBundle = context
                    .new_remove_proposal(&conversation_id.to_vec(), client_id.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&proposal)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::new_external_add_proposal]
    pub fn new_external_add_proposal(
        &self,
        conversation_id: ConversationId,
        epoch: u32,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let proposal_bytes = context
                    .new_external_add_proposal(
                        conversation_id.to_vec(),
                        u64::from(epoch).into(),
                        ciphersuite.into(),
                        credential_type.into(),
                    )
                    .await
                    .map_err(CoreCryptoError::from)?
                    .to_bytes()
                    .map(|bytes| Uint8Array::from(bytes.as_slice()))
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(proposal_bytes.into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<ConversationInitBundle>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::join_by_external_commit]
    pub fn join_by_external_commit(
        &self,
        group_info: Box<[u8]>,
        custom_configuration: CustomConfiguration,
        credential_type: CredentialType,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(MlsError::from)
                    .map_err(CryptoError::from)
                    .map_err(CoreCryptoError::from)?;

                let result: ConversationInitBundle = context
                    .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .try_into()?;

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::merge_pending_group_from_external_commit]
    pub fn merge_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                if let Some(decrypted_messages) = context
                    .merge_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                {
                    let messages = decrypted_messages
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<WasmCryptoResult<Vec<BufferedDecryptedMessage>>>()?;

                    return WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?);
                }

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::clear_pending_group_from_external_commit]
    pub fn clear_pending_group_from_external_commit(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .clear_pending_group_from_external_commit(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::commit_accepted]
    pub fn commit_accepted(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                if let Some(decrypted_messages) = context
                    .commit_accepted(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                {
                    let messages = decrypted_messages
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<WasmCryptoResult<Vec<BufferedDecryptedMessage>>>()?;

                    return WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&messages)?);
                }
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::clear_pending_proposal]
    pub fn clear_pending_proposal(&self, conversation_id: ConversationId, proposal_ref: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .clear_pending_proposal(&conversation_id.to_vec(), proposal_ref.to_vec().into())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::clear_pending_commit]
    pub fn clear_pending_commit(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .clear_pending_commit(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::random_bytes]
    pub fn random_bytes(&self, len: usize) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let bytes = context.random_bytes(len).map_err(CoreCryptoError::from).await?;
                WasmCryptoResult::Ok(Uint8Array::from(bytes.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: usize) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let key = context
                    .export_secret_key(&conversation_id.to_vec(), key_length)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_external_sender]
    pub fn get_external_sender(&self, id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ext_sender = context
                    .get_external_sender(&id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(ext_sender.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let clients = context
                    .get_client_ids(&conversation_id.to_vec())
                    .await
                    .map_err(CoreCryptoError::from)?;
                let clients = js_sys::Array::from_iter(
                    clients
                        .into_iter()
                        .map(|client| Uint8Array::from(client.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(clients.into())
            }
            .err_into(),
        )
    }
}
