use rusty_jwt_tools::prelude::{ClientId, Handle};
use x509_cert::{Certificate, anchor::TrustAnchorChoice};

use super::X509CredentialConfiguration;
use crate::{
    acquisition::{error::CertificateError, identity::WireIdentityReader as _},
    pki_env::PkiEnvironment,
    x509_check::revocation::{PkiEnvironment as RjtPkiEnvironment, PkiEnvironmentParams},
};

pub(crate) async fn verify_cert_chain(
    config: &X509CredentialConfiguration,
    pki_env: &PkiEnvironment,
    certs: &[Certificate],
) -> Result<(), CertificateError> {
    // We can be sure there is at least one certificate because the ACME server
    // response was checked prior to calling this function.
    let (leaf, intermediates) = certs.split_first().expect("at least one certificate");

    // TODO: this is ridiculous, once we have the "outer" PKI env, we should
    // be certain that there is also the "inner", RjtPkiEnvironment one. This
    // should be simplified once we drop RjtPkiEnvironment.
    let trust_roots: Vec<TrustAnchorChoice> = pki_env
        .mls_pki_env_provider()
        .get_trust_anchors()
        .iter()
        .map(|ta| ta.decoded_ta.clone())
        .collect();

    let env = RjtPkiEnvironment::init(PkiEnvironmentParams {
        trust_roots: trust_roots.as_slice(),
        intermediates,
        crls: &[],
    })?;

    verify_leaf_certificate(config, &env, leaf)?;

    // see https://datatracker.ietf.org/doc/html/rfc8555#section-11.4
    RjtPkiEnvironment::extract_ski_aki_from_cert(leaf)?;

    Ok(())
}

/// Ensure that the generated certificate matches our expectations, i.e. that the fields in the
/// certificate match configuration values.
fn verify_leaf_certificate(
    config: &X509CredentialConfiguration,
    pki_env: &RjtPkiEnvironment,
    cert: &Certificate,
) -> Result<(), CertificateError> {
    pki_env.validate_cert(cert)?;

    // TODO: verify that cert is signed by enrollment.sign_kp
    let cert_identity = cert.extract_identity(pki_env, config.hash_alg)?;

    let cert_id =
        ClientId::try_from_qualified(&cert_identity.client_id).map_err(|_| CertificateError::InvalidClientId)?;
    if cert_id != config.client_id {
        return Err(CertificateError::ClientIdMismatch);
    }

    if cert_identity.display_name != config.display_name {
        return Err(CertificateError::DisplayNameMismatch);
    }

    let handle = Handle::from(config.handle.as_ref())
        .try_to_qualified(&config.domain)
        .expect("X509 configuration handle and domain must be valid");
    if cert_identity.handle != handle {
        return Err(CertificateError::HandleMismatch);
    }

    if cert_identity.domain != config.domain {
        return Err(CertificateError::DomainMismatch);
    }
    Ok(())
}
