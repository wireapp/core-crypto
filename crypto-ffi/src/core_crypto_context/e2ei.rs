use crate::{
    Ciphersuite, ConversationId, CoreCryptoContext, CoreCryptoError, CoreCryptoResult, CrlRegistration,
    E2eiConversationState, E2eiEnrollment, UserIdentities, WireIdentity, client_id::ClientIdMaybeArc,
    crl::NewCrlDistributionPoints,
};
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::transaction_context::Error as TransactionError;
use std::collections::HashMap;
#[cfg(not(target_family = "wasm"))]
use std::sync::Arc;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(not(target_family = "wasm"))]
type EnrollmentParameter = Arc<E2eiEnrollment>;

#[cfg(target_family = "wasm")]
type EnrollmentParameter = E2eiEnrollment;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCryptoContext {
    /// See [core_crypto::transaction_context::TransactionContext::e2ei_new_enrollment]
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: String,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        self.inner
            .e2ei_new_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                team,
                expiry_sec,
                ciphersuite.into(),
            )
            .await
            .map(E2eiEnrollment::new)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_new_activation_enrollment]
    pub async fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        self.inner
            .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(E2eiEnrollment::new)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_new_rotate_enrollment]
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        self.inner
            .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(E2eiEnrollment::new)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_register_acme_ca]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> CoreCryptoResult<()> {
        self.inner
            .e2ei_register_acme_ca(trust_anchor_pem)
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_register_intermediate_ca_pem]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> CoreCryptoResult<NewCrlDistributionPoints> {
        self.inner
            .e2ei_register_intermediate_ca_pem(cert_pem)
            .await
            .map(Into::into)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_register_crl]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Vec<u8>) -> CoreCryptoResult<CrlRegistration> {
        self.inner
            .e2ei_register_crl(crl_dp, crl_der)
            .await
            .map(Into::into)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_mls_init_only]
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: EnrollmentParameter,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;
        let mut enrollment = enrollment.write().await;
        self.inner
            .e2ei_mls_init_only(&mut enrollment, certificate_chain, nb_key_package)
            .await
            .map(Into::into)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::e2ei_rotate]
    pub async fn e2ei_rotate(&self, conversation_id: &ConversationId) -> CoreCryptoResult<()> {
        let mut conversation = self.inner.conversation(conversation_id).await?;
        conversation.e2ei_rotate(None).await.map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::save_x509_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: EnrollmentParameter,
        certificate_chain: String,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        let mut enrollment = enrollment.write().await;
        self.inner
            .save_x509_credential(&mut enrollment, certificate_chain)
            .await
            .map(Into::into)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::delete_stale_key_packages]
    pub async fn delete_stale_key_packages(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<()> {
        self.inner
            .delete_stale_key_packages(ciphersuite.into())
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_enrollment_stash]
    ///
    /// Note that this can only succeed if the enrollment is unique and there are no other hard refs to it.
    pub async fn e2ei_enrollment_stash(&self, enrollment: EnrollmentParameter) -> CoreCryptoResult<Vec<u8>> {
        #[cfg(not(target_family = "wasm"))]
        let enrollment = Arc::into_inner(enrollment).ok_or_else(|| {
            CoreCryptoError::ad_hoc("outer enrollment had multiple strong refs and could not be unpacked")
        })?;
        let enrollment = enrollment.into_inner().ok_or_else(|| {
            CoreCryptoError::ad_hoc("inner enrollment had multiple strong refs and could not be unpacked")
        })?;

        self.inner
            .e2ei_enrollment_stash(enrollment)
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::transaction_context::TransactionContext::e2ei_enrollment_stash_pop]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: Vec<u8>) -> CoreCryptoResult<E2eiEnrollment> {
        self.inner
            .e2ei_enrollment_stash_pop(handle)
            .await
            .map(E2eiEnrollment::new)
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(
        &self,
        conversation_id: &ConversationId,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let conversation = self.inner.conversation(conversation_id).await?;
        conversation
            .e2ei_conversation_state()
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::prelude::Session::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        self.inner
            .e2ei_is_enabled(sc)
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::mls::conversation::Conversation::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: &ConversationId,
        device_ids: Vec<ClientIdMaybeArc>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.as_cc()).collect::<Vec<_>>();

        let conversation = self.inner.conversation(conversation_id).await?;
        let wire_ids = conversation.get_device_identities(device_ids.as_slice()).await?;
        Ok(wire_ids.into_iter().map(Into::into).collect())
    }

    /// See [core_crypto::mls::conversation::Conversation::get_user_identities]
    #[cfg_attr(
        target_family = "wasm",
        wasm_bindgen(unchecked_return_type = "Map<string, WireIdentity[]>")
    )]
    pub async fn get_user_identities(
        &self,
        conversation_id: &ConversationId,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<UserIdentities> {
        let conversation = self.inner.conversation(conversation_id).await?;
        let user_ids = conversation.get_user_identities(user_ids.as_slice()).await?;
        let user_ids = user_ids
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(WireIdentity::from).collect()))
            .collect::<HashMap<_, Vec<_>>>();
        #[cfg(target_family = "wasm")]
        let user_ids = serde_wasm_bindgen::to_value(&user_ids)?;
        Ok(user_ids)
    }

    /// See [core_crypto::prelude::Session::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> CoreCryptoResult<bool> {
        self.inner
            .e2ei_is_pki_env_setup()
            .await
            .map_err(Into::<TransactionError>::into)
            .map_err(Into::into)
    }
}
