use core_crypto_keystore::Database;
use mls_crypto_provider::EntropySeed;
use typed_builder::TypedBuilder;

use crate::{
    ClientId, INITIAL_KEYING_MATERIAL_COUNT, MlsError,
    mls::{
        ciphersuite::MlsCiphersuite,
        error::{Error, Result},
    },
};

/// Configuration parameters for [Session][crate::mls::session::Session]
///
/// These can be set directly or via the [builder][SessionConfig::builder].
#[derive(Debug, Clone, TypedBuilder)]
pub struct SessionConfig<'a> {
    /// Database to be used to instantiate the [MlsCryptoProvider][mls_crypto_provider::MlsCryptoProvider]
    pub database: Database,
    /// Identifier for the client to be used by [Session][crate::mls::session::Session]
    ///
    /// If set, this initializes the MLS session. Otherwise, the session is left uninitialized.
    #[builder(default, setter(strip_option(fallback = client_id_opt)))]
    pub client_id: Option<ClientId>,
    /// Entropy pool seed for the internal PRNG
    #[builder(default, setter(strip_option(fallback = external_entropy_opt)))]
    pub external_entropy: Option<&'a [u8]>,
    /// All supported ciphersuites in this session
    #[builder(default, setter(transform = |iter: impl IntoIterator<Item = MlsCiphersuite>| iter.into_iter().collect()))]
    pub ciphersuites: Vec<MlsCiphersuite>,
    /// Number of [openmls::prelude::KeyPackage] to create when creating a MLS client.
    ///
    /// Defaults to [crate::INITIAL_KEYING_MATERIAL_COUNT].
    #[builder(default)]
    pub nb_key_packages: Option<usize>,
}

/// Validated configuration parameters for [Session][crate::mls::session::Session].
///
/// These can not be constructed directly, only via [SessionConfig].
#[derive(Debug)]
pub struct ValidatedSessionConfig {
    pub(super) database: Database,
    pub(super) client_id: Option<ClientId>,
    pub(super) external_entropy: Option<EntropySeed>,
    pub(super) ciphersuites: Vec<MlsCiphersuite>,
    pub(super) nb_key_packages: usize,
}

impl<'a> SessionConfig<'a> {
    /// Validate this configuration to produce a validated configuration.
    ///
    /// This can then be passed to [Session::try_new][crate::mls::session::Session::try_new].
    pub fn validate(self) -> Result<ValidatedSessionConfig> {
        let Self {
            database,
            client_id,
            external_entropy,
            ciphersuites,
            nb_key_packages,
        } = self;
        if let Some(client_id) = &client_id
            && client_id.is_empty()
        {
            return Err(Error::MalformedIdentifier("client_id"));
        }

        if client_id.is_some() && ciphersuites.is_empty() {
            return Err(Error::MalformedIdentifier(
                "ciphersuites must be non-empty if initializing (i.e. client_id is set)",
            ));
        }

        let external_entropy = external_entropy
            .map(EntropySeed::try_from_slice)
            .transpose()
            .map_err(MlsError::wrap("gathering external entropy"))?;

        let nb_key_packages = nb_key_packages.unwrap_or(INITIAL_KEYING_MATERIAL_COUNT);

        Ok(ValidatedSessionConfig {
            database,
            client_id,
            external_entropy,
            ciphersuites,
            nb_key_packages,
        })
    }
}

impl<'a> TryFrom<SessionConfig<'a>> for ValidatedSessionConfig {
    type Error = Error;

    fn try_from(value: SessionConfig<'a>) -> std::result::Result<Self, Self::Error> {
        value.validate()
    }
}
