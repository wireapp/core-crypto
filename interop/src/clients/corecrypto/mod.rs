pub(crate) mod android;
pub(crate) mod web;

#[cfg(target_os = "macos")]
pub(crate) mod ios;

/// The init key of a TLS-serialized key package, hex-encoded, for logging.
fn hex_init_key(key_package: &[u8]) -> anyhow::Result<String> {
    use tls_codec::Deserialize as _;

    let key_package = core_crypto::KeyPackageIn::tls_deserialize_exact(key_package)?.validate(
        &core_crypto::RustCrypto::default(),
        openmls::prelude::ProtocolVersion::Mls10,
    )?;
    Ok(hex::encode(key_package.hpke_init_key().as_slice()))
}
