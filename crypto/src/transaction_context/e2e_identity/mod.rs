//! This module contains all behaviour of a transaction context connected to end-to-end identity.

pub(crate) mod conversation_state;
pub mod enabled;
mod error;
mod init_certificates;
mod rotate;
mod stash;

use std::collections::HashMap;

use crate::{
    RecursiveError,
    mls::credential::x509::CertificatePrivateKey,
    prelude::{CertificateBundle, ClientId, ClientIdentifier, E2eiEnrollment, MlsCiphersuite},
};
use openmls_traits::OpenMlsCryptoProvider as _;

use super::TransactionContext;
pub use crate::e2e_identity::E2eiDumpedPkiEnv;
use crate::e2e_identity::NewCrlDistributionPoints;
pub use error::{Error, Result};

impl TransactionContext {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    ///
    /// # Parameters
    /// * `client_id` - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_sec` - generated x509 certificate expiry in seconds
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: ClientId,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: MlsCiphersuite,
    ) -> Result<E2eiEnrollment> {
        let signature_keypair = None; // fresh install without a Basic client. Supplying None will generate a new keypair
        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            &self
                .mls_provider()
                .await
                .map_err(RecursiveError::transaction("getting mls provider"))?,
            ciphersuite,
            signature_keypair,
            #[cfg(not(target_family = "wasm"))]
            None, // fresh install so no refresh token registered yet
        )
        .map_err(RecursiveError::e2e_identity("creating new enrollment"))
        .map_err(Into::into)
    }

    /// Parses the ACME server response from the endpoint fetching x509 certificates and uses it
    /// to initialize the MLS client with a certificate
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
        nb_init_key_packages: Option<usize>,
    ) -> Result<NewCrlDistributionPoints> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("creating new enrollment"))?;
        let cs = *enrollment.ciphersuite();
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                self.mls_provider()
                    .await
                    .map_err(RecursiveError::transaction("getting mls provider"))?
                    .authentication_service()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await
            .map_err(RecursiveError::e2e_identity("getting certificate response"))?;

        let crl_new_distribution_points = self
            .extract_dp_on_init(&certificate_chain[..])
            .await
            .map_err(RecursiveError::mls_credential("extracting dp on init"))?;

        let private_key = CertificatePrivateKey {
            value: sk,
            signature_scheme: cs.signature_algorithm(),
        };

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let identifier = ClientIdentifier::X509(HashMap::from([(cs.signature_algorithm(), cert_bundle)]));
        self.mls_init(identifier, vec![cs], nb_init_key_packages)
            .await
            .map_err(RecursiveError::mls("initializing mls"))?;
        Ok(crl_new_distribution_points)
    }
}

#[cfg(test)]
mod tests {
    use crate::e2e_identity::enrollment::test_utils as e2ei_utils;
    use crate::mls::conversation::Conversation as _;
    use crate::test_utils::x509::X509TestChain;
    use crate::{prelude::*, test_utils::*};
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn e2e_identity_should_work(case: TestContext) {
        use e2ei_utils::E2EI_CLIENT_ID_URI;

        run_test_wo_clients(case.clone(), move |mut cc| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;

                let (mut enrollment, cert) = e2ei_utils::e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
                    is_renewal,
                    e2ei_utils::init_enrollment,
                    e2ei_utils::noop_restore,
                )
                .await
                .unwrap();

                cc.context
                    .e2ei_mls_init_only(&mut enrollment, cert, Some(INITIAL_KEYING_MATERIAL_COUNT))
                    .await
                    .unwrap();

                // verify the created client can create a conversation
                let id = conversation_id();
                cc.context
                    .new_conversation(&id, MlsCredentialType::X509, case.cfg.clone())
                    .await
                    .unwrap();
                cc.context
                    .conversation(&id)
                    .await
                    .unwrap()
                    .encrypt_message("Hello e2e identity !")
                    .await
                    .unwrap();
                assert_eq!(
                    cc.context
                        .conversation(&id)
                        .await
                        .unwrap()
                        .e2ei_conversation_state()
                        .await
                        .unwrap(),
                    E2eiConversationState::Verified
                );
                assert!(cc.context.e2ei_is_enabled(case.signature_scheme()).await.unwrap());
            })
        })
        .await
    }
}
