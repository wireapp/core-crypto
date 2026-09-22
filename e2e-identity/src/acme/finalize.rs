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
    let subject = x509_cert::name::Name::hazmat_from_rdn_sequence(csr_subject(&identifier)?);
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

fn csr_subject(identifier: &CanonicalIdentifier) -> Result<x509_cert::name::DistinguishedName> {
    let dn_domain_oid = const_oid::db::rfc4519::ORGANIZATION_NAME;
    let dn_domain_value =
        x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Utf8String, identifier.domain.as_bytes())?;
    let dn_domain = x509_cert::attr::AttributeTypeAndValue {
        oid: dn_domain_oid,
        value: dn_domain_value,
    };

    // TODO: temporarily using a custom OIDC for carrying the display name without having it listed as a DNS SAN.
    // reusing LDAP's OID for display_name see http://oid-info.com/get/2.16.840.1.113730.3.1.241
    let dn_display_name_oid = const_oid::ObjectIdentifier::new("2.16.840.1.113730.3.1.241")?;
    // let dn_display_name_oid = asn1_rs::oid!(2.16.840 .1 .113730 .3 .1 .241).as_bytes().try_into()?;
    let dn_display_name_value =
        x509_cert::attr::AttributeValue::new(x509_cert::der::Tag::Utf8String, identifier.display_name.as_bytes())?;
    let dn_display_name = x509_cert::attr::AttributeTypeAndValue {
        oid: dn_display_name_oid,
        value: dn_display_name_value,
    };

    let domain = x509_cert::name::RelativeDistinguishedName::try_from(vec![dn_domain])?;
    let display_name = x509_cert::name::RelativeDistinguishedName::try_from(vec![dn_display_name])?;
    let subject = x509_cert::name::DistinguishedName::from(vec![domain, display_name]);
    Ok(subject)
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
