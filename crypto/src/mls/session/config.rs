use core_crypto_keystore::ConnectionType;
use mls_crypto_provider::{DatabaseKey, EntropySeed};
use typed_builder::TypedBuilder;

use crate::{
    MlsError,
    mls::{
        ciphersuite::MlsCiphersuite,
        error::{Error, Result},
    },
    prelude::{ClientId, INITIAL_KEYING_MATERIAL_COUNT},
};

/// Configuration parameters for [Session][crate::mls::session::Session]
///
/// These can be set directly or via the [builder][SessionConfig::builder].
#[derive(Debug, Clone, TypedBuilder)]
pub struct SessionConfig<'a> {
    /// Connection type for the database
    pub db_connection_type: ConnectionType<'a>,
    /// Database key to be used to instantiate the [MlsCryptoProvider][mls_crypto_provider::MlsCryptoProvider]
    pub database_key: DatabaseKey,
    /// Identifier for the client to be used by [Session][crate::mls::session::Session]
    ///
    /// If set, this initializes the MLS session. Otherwise, the session is left uninitialized.
    #[builder(default, setter(strip_option(fallback = client_id_opt)))]
    pub client_id: Option<ClientId>,
    /// Entropy pool seed for the internal PRNG
    #[builder(default, setter(strip_option(fallback = external_entropy_opt)))]
    pub external_entropy: Option<&'a [u8]>,
    /// All supported ciphersuites in this session
    #[builder(default, setter(transform = |iter: impl IntoIterator<Item = MlsCiphersuite>| Some(iter.into_iter().collect())))]
    pub ciphersuites: Option<Vec<MlsCiphersuite>>,
    /// Number of [openmls::prelude::KeyPackage] to create when creating a MLS client.
    ///
    /// Defaults to [crate::prelude::INITIAL_KEYING_MATERIAL_COUNT].
    #[builder(default)]
    pub nb_key_packages: Option<usize>,
}
impl<'a, Key, ClientId, ExternalEntropy, Ciphersuites, KPs>
    SessionConfigBuilder<'a, ((), Key, ClientId, ExternalEntropy, Ciphersuites, KPs)>
{
    /// Use an in-memory database
    pub fn in_memory(
        self,
    ) -> SessionConfigBuilder<'a, ((ConnectionType<'a>,), Key, ClientId, ExternalEntropy, Ciphersuites, KPs)> {
        self.db_connection_type(ConnectionType::InMemory)
    }

    /// Use a persistent database at the given path
    pub fn persistent(
        self,
        path: &'a str,
    ) -> SessionConfigBuilder<'a, ((ConnectionType<'a>,), Key, ClientId, ExternalEntropy, Ciphersuites, KPs)> {
        self.db_connection_type(ConnectionType::Persistent(path))
    }
}

/// Validated configuration parameters for [Session][crate::mls::session::Session].
///
/// These can not be constructed directly, only via [SessionConfig].
#[derive(Debug)]
pub struct ValidatedSessionConfig<'a> {
    pub(super) db_connection_type: ConnectionType<'a>,
    pub(super) database_key: DatabaseKey,
    pub(super) client_id: Option<ClientId>,
    pub(super) external_entropy: Option<EntropySeed>,
    pub(super) ciphersuites: Vec<MlsCiphersuite>,
    pub(super) nb_key_packages: usize,
}

impl<'a> SessionConfig<'a> {
    /// Validate this configuration to produce a validated configuration.
    ///
    /// This can then be passed to [Session::try_new][crate::mls::session::Session::try_new].
    pub fn validate(self) -> Result<ValidatedSessionConfig<'a>> {
        let Self {
            db_connection_type,
            database_key,
            client_id,
            external_entropy,
            ciphersuites,
            nb_key_packages,
        } = self;

        if let ConnectionType::Persistent(path) = &db_connection_type
            && path.trim().is_empty()
        {
            return Err(Error::MalformedIdentifier("persistent db path"));
        }
        if let Some(client_id) = &client_id
            && client_id.is_empty()
        {
            return Err(Error::MalformedIdentifier("client_id"));
        }
        if client_id.is_some() {
            match &ciphersuites {
                None => {
                    return Err(Error::MalformedIdentifier(
                        "ciphersuites must be present if initializing (i.e. client_id is set)",
                    ));
                }
                Some(cs) if cs.is_empty() => {
                    return Err(Error::MalformedIdentifier(
                        "ciphersuites must be non-empty if initializing (i.e. client_id is set)",
                    ));
                }
                _ => {}
            }
        }

        let ciphersuites = ciphersuites.unwrap_or_default();

        let external_entropy = external_entropy
            .map(EntropySeed::try_from_slice)
            .transpose()
            .map_err(MlsError::wrap("gathering external entropy"))?;

        let nb_key_packages = nb_key_packages.unwrap_or(INITIAL_KEYING_MATERIAL_COUNT);

        Ok(ValidatedSessionConfig {
            db_connection_type,
            database_key,
            client_id,
            external_entropy,
            ciphersuites,
            nb_key_packages,
        })
    }
}

impl<'a> TryFrom<SessionConfig<'a>> for ValidatedSessionConfig<'a> {
    type Error = Error;

    fn try_from(value: SessionConfig<'a>) -> std::result::Result<Self, Self::Error> {
        value.validate()
    }
}
