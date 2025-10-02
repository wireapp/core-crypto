use core_crypto_keystore::Database;
use typed_builder::TypedBuilder;

use crate::{
    ClientId,
    mls::{
        ciphersuite::Ciphersuite,
        error::{Error, Result},
    },
};

/// Configuration parameters for [Session][crate::mls::session::Session]
///
/// These can be set directly or via the [builder][SessionConfig::builder].
#[derive(Debug, Clone, TypedBuilder)]
pub struct SessionConfig {
    /// Database to be used to instantiate the [MlsCryptoProvider][mls_crypto_provider::MlsCryptoProvider]
    pub database: Database,
    /// Identifier for the client to be used by [Session][crate::mls::session::Session]
    ///
    /// If set, this initializes the MLS session. Otherwise, the session is left uninitialized.
    #[builder(default, setter(strip_option(fallback = client_id_opt)))]
    pub client_id: Option<ClientId>,
    /// All supported ciphersuites in this session
    #[builder(default, setter(transform = |iter: impl IntoIterator<Item = Ciphersuite>| iter.into_iter().collect()))]
    pub ciphersuites: Vec<Ciphersuite>,
}

/// Validated configuration parameters for [Session][crate::mls::session::Session].
///
/// These can not be constructed directly, only via [SessionConfig].
#[derive(Debug)]
pub struct ValidatedSessionConfig {
    pub(super) database: Database,
    pub(super) client_id: Option<ClientId>,
    pub(super) ciphersuites: Vec<Ciphersuite>,
}

impl SessionConfig {
    /// Validate this configuration to produce a validated configuration.
    ///
    /// This can then be passed to [Session::try_new][crate::mls::session::Session::try_new].
    pub fn validate(self) -> Result<ValidatedSessionConfig> {
        let Self {
            database,
            client_id,
            ciphersuites,
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

        Ok(ValidatedSessionConfig {
            database,
            client_id,
            ciphersuites,
        })
    }
}

impl TryFrom<SessionConfig> for ValidatedSessionConfig {
    type Error = Error;

    fn try_from(value: SessionConfig) -> std::result::Result<Self, Self::Error> {
        value.validate()
    }
}
