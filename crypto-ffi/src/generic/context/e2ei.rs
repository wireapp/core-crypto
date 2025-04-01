use std::{collections::HashMap, ops::DerefMut};

use crate::{
    Ciphersuite, ClientId, CoreCryptoContext, CoreCryptoError, CoreCryptoResult, CredentialType, CrlRegistration,
    E2eiConversationState, E2eiDumpedPkiEnv, E2eiEnrollment, NewCrlDistributionPoints, WireIdentity,
};
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::{RecursiveError, prelude::VerifiableGroupInfo};
use tls_codec::Deserialize;

#[uniffi::export]
impl CoreCryptoContext {
    /// See [core_crypto::context::CentralContext::e2ei_new_enrollment]
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
            .map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::e2ei_new_activation_enrollment]
    pub async fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .inner
            .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(E2eiEnrollment::new)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_new_rotate_enrollment]
    pub async fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .inner
            .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(E2eiEnrollment::new)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_acme_ca]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> CoreCryptoResult<()> {
        self.inner.e2ei_register_acme_ca(trust_anchor_pem).await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_intermediate_ca_pem]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> CoreCryptoResult<NewCrlDistributionPoints> {
        Ok(self
            .inner
            .e2ei_register_intermediate_ca_pem(cert_pem)
            .await
            .map(|new_crl_distribution_point| -> Option<Vec<_>> { new_crl_distribution_point.into() })?
            .into())
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_crl]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Vec<u8>) -> CoreCryptoResult<CrlRegistration> {
        Ok(self.inner.e2ei_register_crl(crl_dp, crl_der).await.map(Into::into)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_mls_init_only]
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;

        Ok(self
            .inner
            .e2ei_mls_init_only(enrollment.write().await.deref_mut(), certificate_chain, nb_key_package)
            .await
            .map(|new_crl_distribution_point| -> Option<Vec<_>> { new_crl_distribution_point.into() })?
            .into())
    }

    /// See [core_crypto::mls::conversation::ConversationGuard::e2ei_rotate]
    pub async fn e2ei_rotate(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self
            .inner
            .conversation(&conversation_id)
            .await?
            .e2ei_rotate(None)
            .await?)
    }

    /// See [core_crypto::context::CentralContext::save_x509_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
    ) -> CoreCryptoResult<NewCrlDistributionPoints> {
        Ok(self
            .inner
            .save_x509_credential(enrollment.write().await.deref_mut(), certificate_chain)
            .await
            .map(|new_crl_distribution_point| -> Option<Vec<_>> { new_crl_distribution_point.into() })?
            .into())
    }

    /// See [core_crypto::context::CentralContext::delete_stale_key_packages]
    pub async fn delete_stale_key_packages(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<()> {
        self.inner
            .delete_stale_key_packages(ciphersuite.into())
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::context::CentralContext::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash(&self, enrollment: std::sync::Arc<E2eiEnrollment>) -> CoreCryptoResult<Vec<u8>> {
        let enrollment = std::sync::Arc::into_inner(enrollment).ok_or_else(|| {
            CoreCryptoError::Other("outer enrollment had multiple strong refs and could not be unpacked".into())
        })?;
        let enrollment = enrollment.into_inner().ok_or_else(|| {
            CoreCryptoError::Other("inner enrollment had multiple strong refs and could not be unpacked".into())
        })?;

        Ok(self.inner.e2ei_enrollment_stash(enrollment).await?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_enrollment_stash_pop]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: Vec<u8>) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .inner
            .e2ei_enrollment_stash_pop(handle)
            .await
            .map(E2eiEnrollment::new)?)
    }

    /// See [core_crypto::mls::conversation::conversation_guard::ConversationGuard::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<E2eiConversationState> {
        Ok(self
            .inner
            .conversation(&conversation_id)
            .await?
            .e2ei_conversation_state()
            .await
            .map(Into::into)?)
    }

    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        Ok(self.inner.e2ei_dump_pki_env().await?.map(Into::into))
    }

    /// See [core_crypto::mls::Client::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> CoreCryptoResult<bool> {
        Ok(self.inner.e2ei_is_pki_env_setup().await?)
    }

    /// See [core_crypto::mls::Client::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        Ok(self.inner.e2ei_is_enabled(sc).await?)
    }

    /// See [core_crypto::mls::Client::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: Vec<u8>,
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.0).collect::<Vec<_>>();
        Ok(self
            .inner
            .conversation(&conversation_id)
            .await?
            .get_device_identities(&device_ids[..])
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
    }

    /// See [core_crypto::mls::Client::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: Vec<u8>,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<HashMap<String, Vec<WireIdentity>>> {
        Ok(self
            .inner
            .conversation(&conversation_id)
            .await?
            .get_user_identities(&user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::Client::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: CredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("getting credential in use"))?;
        Ok(self
            .inner
            .get_credential_in_use(group_info, credential_type.into())
            .await?
            .into())
    }
}
