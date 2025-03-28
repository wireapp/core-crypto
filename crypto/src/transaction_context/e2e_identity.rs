use crate::{
    RecursiveError,
    e2e_identity::init_certificates::NewCrlDistributionPoint,
    prelude::{ClientId, E2eiEnrollment, MlsCiphersuite},
};
use openmls_traits::OpenMlsCryptoProvider as _;

use super::{Error, Result, TransactionContext};

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
                .map_err(RecursiveError::root("getting mls provider"))?,
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
    ) -> Result<NewCrlDistributionPoint> {
        let sk = enrollment
            .get_sign_key_for_mls()
            .map_err(RecursiveError::e2e_identity("creating new enrollment"))
            .map_err(Into::into)?;
        let cs = enrollment.ciphersuite();
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                self.mls_provider()
                    .await
                    .map_err(RecursiveError::root("getting mls provider"))?
                    .authentication_service()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(Error::PkiEnvironmentUnset)?,
            )
            .await?;

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
