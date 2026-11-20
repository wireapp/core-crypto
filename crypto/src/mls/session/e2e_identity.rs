use openmls::{
    group::MlsGroup,
    prelude::{Credential, group_info::VerifiableGroupInfo},
};
use wire_e2e_identity::WireIdentityReader as _;

use super::{Result, Session};
use crate::{
    CredentialType, E2eiConversationState, OpenMlsError,
    mls::credential::{ext::CredentialExt as _, identity::is_time_valid},
    mls_provider::{AuthenticationService, MlsProvider},
};

impl Session {
    /// Verifies a Group state before joining it
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        let Ok(credentials) = Self::verified_member_credentials(&self.crypto_provider.read_only(), group_info) else {
            return Ok(E2eiConversationState::NotVerified);
        };

        Ok(Self::compute_conversation_state(
            credentials.iter(),
            CredentialType::X509,
            self.crypto_provider.authentication_service(),
        )
        .await)
    }

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
    /// turned on or not before joining it.
    pub async fn get_credential_in_use(
        &self,
        group_info: VerifiableGroupInfo,
        credential_type: CredentialType,
    ) -> Result<E2eiConversationState> {
        let credentials = Self::verified_member_credentials(&self.crypto_provider.read_only(), group_info)?;
        Ok(Self::compute_conversation_state(
            credentials.iter(),
            credential_type,
            self.crypto_provider.authentication_service(),
        )
        .await)
    }

    /// The credentials of the members of the group a GroupInfo describes.
    ///
    /// Not verifying a GroupInfo could let attackers lure clients about the e2ei state of a conversation, and as a
    /// consequence degrade the conversation for all participants once joining it. So openmls verifies the GroupInfo
    /// and the ratchet tree in its extension first.
    pub(crate) fn verified_member_credentials(
        provider: &MlsProvider<'_>,
        group_info: VerifiableGroupInfo,
    ) -> Result<Vec<Credential>> {
        Ok(MlsGroup::external_commit_builder()
            .verify_group(provider, group_info)
            .map_err(OpenMlsError::wrap("verifying group info and ratchet tree"))?
            .members()
            .map(|member| member.credential)
            .collect())
    }

    /// _credential_type will be used in the future to get the usage of VC Credentials, even Basics one.
    /// Right now though, we do not need anything other than X509 so let's keep things simple.
    pub(crate) async fn compute_conversation_state<'a>(
        credentials: impl Iterator<Item = &'a Credential>,
        _credential_type: CredentialType,
        auth_service: &AuthenticationService,
    ) -> E2eiConversationState {
        let pki_env = auth_service.pki_env().await;
        let Some(env) = pki_env else {
            return E2eiConversationState::NotEnabled;
        };

        let mut is_e2ei = false;
        let mut state = E2eiConversationState::Verified;

        for credential in credentials {
            let Ok(Some(cert)) = credential.parse_leaf_cert() else {
                state = E2eiConversationState::NotVerified;
                if is_e2ei {
                    break;
                }
                continue;
            };

            is_e2ei = true;

            let invalid_identity = cert.extract_identity(&env).await.is_err();

            let is_time_invalid = !is_time_valid(&cert);
            let is_revoked_or_invalid = env.validate_cert(&cert).await.is_err();
            let is_invalid = invalid_identity || is_time_invalid || is_revoked_or_invalid;
            if is_invalid {
                state = E2eiConversationState::NotVerified;
                break;
            }
        }

        if is_e2ei {
            state
        } else {
            E2eiConversationState::NotEnabled
        }
    }
}
