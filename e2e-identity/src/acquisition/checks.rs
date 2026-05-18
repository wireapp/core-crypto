use rusty_jwt_tools::prelude::{ClientId, Handle, Pem};
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
    sign_kp: &Pem,
    certs: &[Certificate],
) -> Result<(), CertificateError> {
    // We can be sure there is at least one certificate because the ACME server
    // response was checked prior to calling this function.
    let (leaf, intermediates) = certs.split_first().expect("at least one certificate");

    let trust_anchors: Vec<TrustAnchorChoice> = pki_env
        .get_trust_anchors()
        .await
        .into_iter()
        .map(TrustAnchorChoice::Certificate)
        .collect();

    let env = RjtPkiEnvironment::init(PkiEnvironmentParams {
        trust_roots: trust_anchors.as_slice(),
        intermediates,
        crls: &[],
    })?;

    verify_leaf_certificate(config, &env, pki_env, sign_kp, leaf).await?;

    // see https://datatracker.ietf.org/doc/html/rfc8555#section-11.4
    RjtPkiEnvironment::extract_ski_aki_from_cert(leaf)?;

    Ok(())
}

/// Ensure that the generated certificate matches our expectations, i.e. that the fields in the
/// certificate match configuration values.
async fn verify_leaf_certificate(
    config: &X509CredentialConfiguration,
    pki_env: &RjtPkiEnvironment,
    outer_pki_env: &PkiEnvironment,
    sign_kp: &Pem,
    cert: &Certificate,
) -> Result<(), CertificateError> {
    pki_env.validate_cert(cert)?;

    // Make sure that the algorithm specified by the certificate matches the one of the signing
    // keypair.
    let alg = crate::utils::jws_alg_to_x509_identifier(config.sign_alg);
    if cert.tbs_certificate.subject_public_key_info.algorithm != alg {
        return Err(CertificateError::AlgorithmMismatch);
    }

    // Make sure that the public key in the certificate matches the one from the signing keypair.
    // Note that we expect to always get proper PEM data here since that data is generated
    // internally, when starting acquisition; if the expect fails, that means the implementation is
    // broken.
    let sign_kp_bytes = crate::utils::public_key_bytes(config.sign_alg, sign_kp).expect("sign_kp must be valid PEM");
    let cert_pubkey_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if sign_kp_bytes != cert_pubkey_bytes {
        return Err(CertificateError::KeyMismatch);
    }

    let cert_identity = cert.extract_identity(outer_pki_env, config.hash_alg).await?;

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
