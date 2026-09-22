use std::str::FromStr as _;

use base64::Engine as _;
use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem};
use x509_cert::{
    builder::Builder as _,
    der::Encode as _,
    ext::pkix::{SubjectAltName, name::GeneralName},
};

use crate::acme::{AcmeAccount, AcmeJws, AcmeOrder, Result, identifier::CanonicalIdentifier, order::AcmeOrderError};

/// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
pub(crate) fn finalize_req(
    order: &AcmeOrder,
    account: &AcmeAccount,
    alg: JwsAlgorithm,
    acme_kp: &Pem,
    signing_kp: &Pem,
    previous_nonce: String,
) -> Result<AcmeJws> {
    // Extract the account URL from previous response which created a new account
    let acct_url = account.acct_url()?;
    order.verify()?;
    let csr = generate_csr(alg, order.try_get_coalesce_identifier()?, signing_kp)?;
    let payload = AcmeFinalizeRequest { csr };
    let req = AcmeJws::new(
        alg,
        previous_nonce,
        &order.finalize,
        Some(&acct_url),
        Some(payload),
        acme_kp,
    )?;
    Ok(req)
}

fn uri(value: &str) -> Result<GeneralName> {
    Ok(GeneralName::UniformResourceIdentifier(
        x509_cert::der::asn1::Ia5String::new(value)?,
    ))
}

fn generate_csr(alg: JwsAlgorithm, identifier: CanonicalIdentifier, kp: &Pem) -> Result<String> {
    // TODO: temporarily using a custom OID for carrying the display name without having it listed as a DNS SAN.
    // reusing LDAP's OID for display_name see https://www.rfc-editor.org/info/rfc2798/#section-2.3
    let subject = format!(
        "{}={},O={}",
        const_oid::db::rfc2798::DISPLAY_NAME,
        identifier.display_name,
        identifier.domain
    );
    let subject = x509_cert::name::Name::from_str(&subject)?;

    let mut builder = x509_cert::builder::RequestBuilder::new(subject)?;

    builder.add_extension(&SubjectAltName(vec![
        uri(&identifier.client_id)?,
        uri(&identifier.handle)?,
    ]))?;

    let csr = match alg {
        JwsAlgorithm::Ed25519 => {
            let kp_bytes = ed25519_dalek::pkcs8::KeypairBytes::from_str(kp.as_ref())?;
            let signing_key = ed25519_dalek::SigningKey::try_from(kp_bytes)?;
            builder.build(&signing_key)?
        }
        JwsAlgorithm::P256 => {
            let sk = p256::ecdsa::SigningKey::from_str(kp)?;
            builder.build::<_, p256::ecdsa::DerSignature>(&sk)?
        }
        JwsAlgorithm::P384 => {
            let sk = p384::ecdsa::SigningKey::from_str(kp)?;
            builder.build::<_, p384::ecdsa::DerSignature>(&sk)?
        }
        JwsAlgorithm::P521 => {
            let sk = p521::ecdsa::SigningKey::from_str(kp)?;
            builder.build::<_, p521::ecdsa::DerSignature>(&sk)?
        }
    };

    let csr = csr.to_der()?;
    let csr = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(csr);
    Ok(csr)
}

/// see [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4)
pub(crate) fn finalize_response(response: serde_json::Value) -> Result<AcmeFinalize> {
    let finalize = serde_json::from_value::<AcmeFinalize>(response)?;
    Ok(finalize)
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AcmeFinalizeError(#[from] AcmeOrderError);

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeFinalizeRequest {
    /// Certificate Signing Request,
    /// DER representation encoded using url-safe base64, without padding.
    csr: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AcmeFinalize {
    pub certificate: url::Url,
    #[serde(flatten)]
    pub order: AcmeOrder,
}
