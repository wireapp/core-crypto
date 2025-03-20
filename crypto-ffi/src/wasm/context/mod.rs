#[cfg(target_family = "wasm")]
use crate::lower_ciphersuites;
use crate::{
    Ciphersuite, ConversationConfiguration, CoreCryptoContext, CoreCryptoError, CoreCryptoResult, CredentialType,
    CustomConfiguration, DecryptedMessage, FfiClientId, WasmCryptoResult, WelcomeBundle,
};
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::mls::conversation::Error as ConversationError;
use core_crypto::{
    RecursiveError,
    prelude::{
        CiphersuiteName, ClientId, ClientIdentifier, ConversationId, KeyPackageIn, KeyPackageRef,
        MlsConversationConfiguration, VerifiableGroupInfo,
    },
};
use futures_util::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use tls_codec::{Deserialize, Serialize};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::future_to_promise;

pub mod e2ei;
pub mod proteus;

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
                    .expect("we never run corecrypto on systems with architectures narrower than 32 bits");
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
                    .await
                    .map_err(RecursiveError::mls_client("getting or creating client keypackage"))?
                    .into_iter()
                    .map(|kpb| kpb.tls_serialize_detached())
                    .collect::<Result<Vec<Vec<u8>>, _>>()
                    .map_err(core_crypto::mls::conversation::Error::tls_serialize("keypackages"))
                    .map_err(RecursiveError::mls_conversation("serializing client keypackages"))?;

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
                    .map_err(RecursiveError::mls_client("counting valid client keypackages"))?;
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
                    .map_err(RecursiveError::mls_client("deleting keypackages"))?;
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
        config: ConversationConfiguration,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let mut lower_cfg = MlsConversationConfiguration {
                    custom: config.custom.into(),
                    ..Default::default()
                };

                let mls_ciphersuite: CiphersuiteName = config.ciphersuite.into();
                lower_cfg.ciphersuite = mls_ciphersuite.into();

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
    /// see [core_crypto::mls::conversation::ConversationGuard::epoch]
    pub fn conversation_epoch(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let conversation = context.conversation(&conversation_id).await?;
                WasmCryptoResult::Ok(conversation.epoch().await.into())
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
                let ciphersuite: Ciphersuite = context.conversation(&conversation_id).await?.ciphersuite().await.into();
                WasmCryptoResult::Ok(ciphersuite.into())
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

    /// Returns: [`WasmCryptoResult<Option<Vec<String>>>`]
    ///
    /// see [core_crypto::mls::conversation::conversation_guard::ConversationGuard::add_members]
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
                            .map_err(|e| CoreCryptoError::from(crate::MlsError::Other(e.to_string())))
                    })
                    .collect::<CoreCryptoResult<Vec<_>>>()?;

                let new_crl_distribution_point = context
                    .conversation(&conversation_id)
                    .await?
                    .add_members(key_packages)
                    .await?;
                let new_crl_distribution_point: Option<Vec<String>> = new_crl_distribution_point.into();
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&new_crl_distribution_point)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
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

                context
                    .conversation(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                    .remove_members(&clients)
                    .await
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::mls::conversation::ConversationGuard::mark_as_child_of]
    pub fn mark_conversation_as_child_of(&self, child_id: Box<[u8]>, parent_id: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .conversation(&child_id.into())
                    .await?
                    .mark_as_child_of(&parent_id.into())
                    .await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult()`]
    ///
    /// see [core_crypto::mls::context::CentralContext::update_keying_material]
    pub fn update_keying_material(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .conversation(&conversation_id)
                    .await
                    .map_err(CoreCryptoError::from)?
                    .update_key_material()
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult()`]
    ///
    /// see [core_crypto::mls::context::CentralContext::commit_pending_proposals]
    pub fn commit_pending_proposals(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .conversation(&conversation_id)
                    .await?
                    .commit_pending_proposals()
                    .await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
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
    /// see [core_crypto::mls::conversation::conversation_guard::ConversationGuard::decrypt_message]
    pub fn decrypt_message(&self, conversation_id: ConversationId, payload: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let result = context
                    .conversation(&conversation_id)
                    .await?
                    .decrypt_message(&payload)
                    .await;
                let decrypted_message = if let Err(ConversationError::PendingConversation(mut pending)) = result {
                    pending.try_process_own_join_commit(&payload).await
                } else {
                    result
                }?;

                let decrypted_message = DecryptedMessage::try_from(decrypted_message)?;
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&decrypted_message)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// see [core_crypto::mls::conversation::conversation_guard::ConversationGuard::encrypt_message]
    pub fn encrypt_message(&self, conversation_id: ConversationId, message: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ciphertext = context
                    .conversation(&conversation_id)
                    .await?
                    .encrypt_message(message)
                    .await
                    .map(|ciphertext| Uint8Array::from(ciphertext.as_slice()))
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(ciphertext.into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<WelcomeBundle>`]
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
                    .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                        "verifiable group info",
                    ))
                    .map_err(RecursiveError::mls_conversation("joining by external commit"))?;

                let result: WelcomeBundle = context
                    .join_by_external_commit(group_info, custom_configuration.into(), credential_type.into())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into();

                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&result)?)
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
    /// see [core_crypto::mls::conversation::ImmutableConversation::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: usize) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let key = context
                    .conversation(&conversation_id.to_vec())
                    .await?
                    .export_secret_key(key_length)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// see [core_crypto::mls::conversation::ImmutableConversation::get_external_sender]
    pub fn get_external_sender(&self, id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let ext_sender = context
                    .conversation(&id.to_vec())
                    .await?
                    .get_external_sender()
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(ext_sender.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// see [core_crypto::conversation::ImmutableConversation::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let client_ids = context
                    .conversation(&conversation_id.to_vec())
                    .await?
                    .get_client_ids()
                    .await;
                let client_ids = js_sys::Array::from_iter(
                    client_ids
                        .into_iter()
                        .map(|client| Uint8Array::from(client.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(client_ids.into())
            }
            .err_into(),
        )
    }
}
