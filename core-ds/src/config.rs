#![allow(dead_code)]

use crate::DsResult;

#[cfg(feature = "local-selfcert")]
struct SkipServerVerification;

#[cfg(feature = "local-selfcert")]
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::Certificate,
        _: &[rustls::Certificate],
        _: &rustls::ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

#[cfg(feature = "local-selfcert")]
pub fn configure_client() -> quinn::ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(std::sync::Arc::new(SkipServerVerification))
        .with_no_client_auth();

    quinn::ClientConfig::new(std::sync::Arc::new(crypto))
}

#[cfg(not(feature = "local-selfcert"))]
pub fn configure_client() -> quinn::ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults();

    quinn::ClientConfig::new(std::sync::Arc::new(crypto))
}

pub fn configure_server() -> DsResult<(quinn::ServerConfig, Vec<u8>)> {
    let (cert_der, key_der) = if cfg!(feature = "local-selfcert") {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();
        (cert_der, key_der)
    } else {
        // TODO: find cert/key from env and load them up
        todo!()
    };
    let priv_key = rustls::PrivateKey(key_der);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let server_config = quinn::ServerConfig::with_single_cert(cert_chain, priv_key)?;

    Ok((server_config, cert_der))
}
