use openmls::{
    prelude::{Credential, Node, group_info::VerifiableGroupInfo},
    treesync::RatchetTree,
};
use openmls_traits::OpenMlsCryptoProvider as _;
use wire_e2e_identity::WireIdentityReader as _;

use super::{Result, Session};
use crate::{
    CredentialType, E2eiConversationState, OpenMlsError, mls::credential::ext::CredentialExt as _,
    mls_provider::AuthenticationService,
};

impl Session {
    /// Verifies a Group state before joining it
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        let is_sender = true; // verify the ratchet tree as sender to turn on hardened verification
        let Ok(rt) = group_info.take_ratchet_tree(&self.crypto_provider, is_sender).await else {
            return Ok(E2eiConversationState::NotVerified);
        };

        let credentials = rt.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });

        Ok(Self::compute_conversation_state(
            credentials,
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
        // Not verifying the supplied the GroupInfo here could let attackers lure the clients about
        // the e2ei state of a conversation and as a consequence degrade this conversation for all
        // participants once joining it.
        // This 👇 verifies the GroupInfo and the RatchetTree btw
        let rt = group_info
            .take_ratchet_tree(&self.crypto_provider, false)
            .await
            .map_err(OpenMlsError::wrap("taking ratchet tree"))?;
        Self::get_credential_in_use_in_ratchet_tree(rt, credential_type, self.crypto_provider.authentication_service())
            .await
    }
    pub(crate) async fn get_credential_in_use_in_ratchet_tree(
        ratchet_tree: RatchetTree,
        credential_type: CredentialType,
        auth_service: &AuthenticationService,
    ) -> Result<E2eiConversationState> {
        let credentials = ratchet_tree.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });
        Ok(Self::compute_conversation_state(credentials, credential_type, auth_service).await)
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

            use openmls_x509_credential::X509Ext as _;
            let is_time_valid = cert.is_time_valid().unwrap_or(false);
            let is_time_invalid = !is_time_valid;
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
