use std::{collections::HashMap, ops::DerefMut};

use crate::{
    generic::{
        context::CoreCryptoContext, Ciphersuite, ClientId, CoreCryptoResult, CrlRegistration, E2eiConversationState,
        E2eiDumpedPkiEnv, E2eiEnrollment, MlsCredentialType, WireIdentity,
    },
    CoreCryptoError,
};
use core_crypto::{prelude::VerifiableGroupInfo, RecursiveError};
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
        self.context
            .e2ei_new_enrollment(
                client_id.into_bytes().into(),
                display_name,
                handle,
                team,
                expiry_sec,
                ciphersuite.into(),
            )
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)
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
            .context
            .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
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
            .context
            .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_acme_ca]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> CoreCryptoResult<()> {
        self.context.e2ei_register_acme_ca(trust_anchor_pem).await?;
        Ok(())
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_intermediate_ca_pem]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> CoreCryptoResult<Option<Vec<String>>> {
        Ok(self
            .context
            .e2ei_register_intermediate_ca_pem(cert_pem)
            .await
            .map(Into::into)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_register_crl]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Vec<u8>) -> CoreCryptoResult<CrlRegistration> {
        Ok(self.context.e2ei_register_crl(crl_dp, crl_der).await.map(Into::into)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_mls_init_only]
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Option<Vec<String>>> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(CoreCryptoError::generic())?;

        Ok(self
            .context
            .e2ei_mls_init_only(
                enrollment.0.write().await.deref_mut(),
                certificate_chain,
                nb_key_package,
            )
            .await
            .map(Into::into)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_rotate]
    pub async fn e2ei_rotate(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<()> {
        Ok(self.context.e2ei_rotate(&conversation_id, None).await?)
    }

    /// See [core_crypto::context::CentralContext::save_x509_credential]
    pub async fn save_x509_credential(
        &self,
        enrollment: std::sync::Arc<E2eiEnrollment>,
        certificate_chain: String,
    ) -> CoreCryptoResult<Option<Vec<String>>> {
        Ok(self
            .context
            .save_x509_credential(enrollment.0.write().await.deref_mut(), certificate_chain)
            .await?
            .into())
    }

    /// See [core_crypto::context::CentralContext::retain_only_key_packages_of_most_recent_x509_credentials]
    pub async fn retain_only_key_packages_of_most_recent_x509_credentials(
        &self,
        ciphersuite: Ciphersuite,
    ) -> CoreCryptoResult<()> {
        Ok(self
            .context
            .retain_only_key_packages_of_most_recent_x509_credentials(ciphersuite.into())
            .await?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_enrollment_stash]
    pub async fn e2ei_enrollment_stash(&self, enrollment: std::sync::Arc<E2eiEnrollment>) -> CoreCryptoResult<Vec<u8>> {
        let enrollment = std::sync::Arc::into_inner(enrollment).ok_or_else(|| {
            CoreCryptoError::Other("enrollment had multiple strong refs and could not be unpacked".into())
        })?;
        let enrollment = std::sync::Arc::into_inner(enrollment.0)
            .ok_or_else(|| {
                CoreCryptoError::Other("enrollment.0 had multiple strong refs and could not be unpacked".into())
            })?
            .into_inner();

        Ok(self.context.e2ei_enrollment_stash(enrollment).await?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_enrollment_stash_pop]
    pub async fn e2ei_enrollment_stash_pop(&self, handle: Vec<u8>) -> CoreCryptoResult<E2eiEnrollment> {
        Ok(self
            .context
            .e2ei_enrollment_stash_pop(handle)
            .await
            .map(async_lock::RwLock::new)
            .map(std::sync::Arc::new)
            .map(E2eiEnrollment)?)
    }

    /// See [core_crypto::context::CentralContext::e2ei_conversation_state]
    pub async fn e2ei_conversation_state(&self, conversation_id: Vec<u8>) -> CoreCryptoResult<E2eiConversationState> {
        Ok(self
            .context
            .e2ei_conversation_state(&conversation_id)
            .await
            .map(Into::into)?)
    }

    pub async fn e2ei_dump_pki_env(&self) -> CoreCryptoResult<Option<E2eiDumpedPkiEnv>> {
        Ok(self.context.e2ei_dump_pki_env().await?.map(Into::into))
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> CoreCryptoResult<bool> {
        Ok(self.context.e2ei_is_pki_env_setup().await?)
    }

    /// See [core_crypto::mls::MlsCentral::e2ei_is_enabled]
    pub async fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> CoreCryptoResult<bool> {
        let sc = core_crypto::prelude::MlsCiphersuite::from(core_crypto::prelude::CiphersuiteName::from(ciphersuite))
            .signature_algorithm();
        Ok(self.context.e2ei_is_enabled(sc).await?)
    }

    /// See [core_crypto::mls::MlsCentral::get_device_identities]
    pub async fn get_device_identities(
        &self,
        conversation_id: Vec<u8>,
        device_ids: Vec<ClientId>,
    ) -> CoreCryptoResult<Vec<WireIdentity>> {
        let device_ids = device_ids.into_iter().map(|cid| cid.0).collect::<Vec<_>>();
        Ok(self
            .context
            .get_device_identities(&conversation_id, &device_ids[..])
            .await?
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
    }

    /// See [core_crypto::mls::MlsCentral::get_user_identities]
    pub async fn get_user_identities(
        &self,
        conversation_id: Vec<u8>,
        user_ids: Vec<String>,
    ) -> CoreCryptoResult<HashMap<String, Vec<WireIdentity>>> {
        Ok(self
            .context
            .get_user_identities(&conversation_id, &user_ids[..])
            .await?
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
            .collect::<HashMap<String, Vec<WireIdentity>>>())
    }

    /// See [core_crypto::mls::MlsCentral::get_credential_in_use]
    pub async fn get_credential_in_use(
        &self,
        group_info: Vec<u8>,
        credential_type: MlsCredentialType,
    ) -> CoreCryptoResult<E2eiConversationState> {
        let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_slice())
            .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                "verifiable group info",
            ))
            .map_err(RecursiveError::mls_conversation("getting credential in use"))?;
        Ok(self
            .context
            .get_credential_in_use(group_info, credential_type.into())
            .await?
            .into())
    }
}
