use openmls::{
    prelude::{Credential, Node, SignatureScheme, group_info::VerifiableGroupInfo},
    treesync::RatchetTree,
};
use wire_e2e_identity::prelude::WireIdentityReader as _;

use crate::{
    MlsError, RecursiveError,
    e2e_identity::E2eiDumpedPkiEnv,
    mls::client::CredentialExt as _,
    prelude::{E2eiConversationState, MlsCiphersuite, MlsCredentialType},
};
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{Client, Error, Result};

impl Client {
    /// Returns whether the E2EI PKI environment is setup (i.e. Root CA, Intermediates, CRLs)
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.mls_backend.is_pki_env_setup().await
    }

    /// Dumps the PKI environment as PEM
    pub async fn e2ei_dump_pki_env(&self) -> Result<Option<E2eiDumpedPkiEnv>> {
        if !self.e2ei_is_pki_env_setup().await {
            return Ok(None);
        }
        let pki_env_lock = self.mls_backend.authentication_service().borrow().await;
        let Some(pki_env) = &*pki_env_lock else {
            return Ok(None);
        };
        E2eiDumpedPkiEnv::from_pki_env(pki_env)
            .await
            .map_err(RecursiveError::e2e_identity("dumping pki env"))
            .map_err(Into::into)
    }

    /// Returns true when end-to-end-identity is enabled for the given SignatureScheme
    pub async fn e2ei_is_enabled(&self, signature_scheme: SignatureScheme) -> Result<bool> {
        let x509_result = self
            .find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::X509)
            .await;
        match x509_result {
            Err(Error::CredentialNotFound(MlsCredentialType::X509)) => {
                self.find_most_recent_credential_bundle(signature_scheme, MlsCredentialType::Basic)
                    .await?;
                Ok(false)
            }
            Err(e) => Err(e),
            Ok(_) => Ok(true),
        }
    }

    /// Verifies a Group state before joining it
    pub async fn e2ei_verify_group_state(&self, group_info: VerifiableGroupInfo) -> Result<E2eiConversationState> {
        self.mls_backend
            .authentication_service()
            .refresh_time_of_interest()
            .await;

        let cs = group_info.ciphersuite().into();

        let is_sender = true; // verify the ratchet tree as sender to turn on hardened verification
        let Ok(rt) = group_info.take_ratchet_tree(&self.mls_backend, is_sender).await else {
            return Ok(E2eiConversationState::NotVerified);
        };

        let credentials = rt.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });

        Ok(Self::compute_conversation_state(
            cs,
            credentials,
            MlsCredentialType::X509,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
        .await)
    }

    /// Gets the e2ei conversation state from a `GroupInfo`. Useful to check if the group has e2ei
    /// turned on or not before joining it.
    pub async fn get_credential_in_use(
        &self,
        group_info: VerifiableGroupInfo,
        credential_type: MlsCredentialType,
    ) -> Result<E2eiConversationState> {
        let cs = group_info.ciphersuite().into();
        // Not verifying the supplied the GroupInfo here could let attackers lure the clients about
        // the e2ei state of a conversation and as a consequence degrade this conversation for all
        // participants once joining it.
        // This 👇 verifies the GroupInfo and the RatchetTree btw
        let rt = group_info
            .take_ratchet_tree(&self.mls_backend, false)
            .await
            .map_err(MlsError::wrap("taking ratchet tree"))?;
        Self::get_credential_in_use_in_ratchet_tree(
            cs,
            rt,
            credential_type,
            self.mls_backend.authentication_service().borrow().await.as_ref(),
        )
        .await
    }
    pub(crate) async fn get_credential_in_use_in_ratchet_tree(
        ciphersuite: MlsCiphersuite,
        ratchet_tree: RatchetTree,
        credential_type: MlsCredentialType,
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> Result<E2eiConversationState> {
        let credentials = ratchet_tree.iter().filter_map(|n| match n {
            Some(Node::LeafNode(ln)) => Some(ln.credential()),
            _ => None,
        });
        Ok(Self::compute_conversation_state(ciphersuite, credentials, credential_type, env).await)
    }

    /// _credential_type will be used in the future to get the usage of VC Credentials, even Basics one.
    /// Right now though, we do not need anything other than X509 so let's keep things simple.
    pub(crate) async fn compute_conversation_state<'a>(
        ciphersuite: MlsCiphersuite,
        credentials: impl Iterator<Item = &'a Credential>,
        _credential_type: MlsCredentialType,
        env: Option<&wire_e2e_identity::prelude::x509::revocation::PkiEnvironment>,
    ) -> E2eiConversationState {
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

            let invalid_identity = cert.extract_identity(env, ciphersuite.e2ei_hash_alg()).is_err();

            use openmls_x509_credential::X509Ext as _;
            let is_time_valid = cert.is_time_valid().unwrap_or(false);
            let is_time_invalid = !is_time_valid;
            let is_revoked_or_invalid = env
                .map(|e| e.validate_cert_and_revocation(&cert).is_err())
                .unwrap_or(false);

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
