use core_crypto::CryptoError;
use core_crypto::mls::MlsCentral;
use core_crypto::prelude::{MlsCentralConfiguration, MlsCiphersuite};

uniffi::setup_scaffolding!("test_crate");

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreCryptoError {
    #[error("")]
    CryptoError 
}

pub type CoreCryptoResult<T> = Result<T, CoreCryptoError>;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct ClientId(core_crypto::prelude::ClientId);

uniffi::custom_type!(ClientId, Vec<u8>);

impl UniffiCustomTypeConverter for ClientId {
    type Builtin = Vec<u8>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        Ok(Self(core_crypto::prelude::ClientId::from(val)))
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.to_vec()
    }
}

#[derive(Debug, Default, Clone)]
pub struct Ciphersuites(Vec<core_crypto::prelude::CiphersuiteName>);

impl From<Vec<core_crypto::prelude::CiphersuiteName>> for Ciphersuites {
    fn from(cs: Vec<core_crypto::prelude::CiphersuiteName>) -> Self {
        Self(cs)
    }
}

impl From<Ciphersuites> for Vec<core_crypto::prelude::CiphersuiteName> {
    fn from(cs: Ciphersuites) -> Self {
        cs.0
    }
}

impl<'a> From<&'a Ciphersuites> for Vec<MlsCiphersuite> {
    fn from(cs: &'a Ciphersuites) -> Self {
        cs.0.iter().fold(Vec::with_capacity(cs.0.len()), |mut acc, c| {
            acc.push((*c).into());
            acc
        })
    }
}

uniffi::custom_type!(Ciphersuites, Vec<u16>);

impl UniffiCustomTypeConverter for Ciphersuites {
    type Builtin = Vec<u16>;

    fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
        val.iter().try_fold(Self(vec![]), |mut acc, c| -> uniffi::Result<Self> {
            let cs = core_crypto::prelude::CiphersuiteName::try_from(*c)
                .map(Into::into)
                .map_err(|_| CoreCryptoError::CryptoError)?;
            acc.0.push(cs);
            Ok(acc)
        })
    }

    fn from_custom(obj: Self) -> Self::Builtin {
        obj.0.into_iter().map(|c| (&c).into()).collect()
    }
}

#[derive(uniffi::Object)]
pub struct CoreCrypto {
    central: async_lock::Mutex<core_crypto::CoreCrypto>,
    proteus_last_error_code: std::sync::atomic::AtomicU32,
}

impl CoreCrypto {
    #[uniffi::constructor]
    pub async fn new(
        path: String,
        key: String,
        client_id: Option<ClientId>,
        ciphersuites: Option<Ciphersuites>,
        nb_key_package: Option<u32>,
    ) -> CoreCryptoResult<Self> {
        let nb_key_package = nb_key_package
            .map(usize::try_from)
            .transpose()
            .map_err(|e| CoreCryptoError::CryptoError)?;
        let ciphersuites = ciphersuites.unwrap_or_default().into();
        let configuration = MlsCentralConfiguration::try_new(
            path,
            key,
            client_id.map(|cid| cid.0.clone()),
            ciphersuites,
            None,
            nb_key_package,
        ).map_err(|e| CoreCryptoError::CryptoError)?;

        let central = MlsCentral::try_new(configuration).await.map_err(|e| CoreCryptoError::CryptoError)?;
        let central = core_crypto::CoreCrypto::from(central).into();

        Ok(CoreCrypto {
            central,
            proteus_last_error_code: std::sync::atomic::AtomicU32::new(0),
        })
    }
}

#[uniffi::export]
/// See [core_crypto::mls::MlsCentral::try_new]
pub async fn core_crypto_new(
    path: String,
    key: String,
    client_id: ClientId,
    ciphersuites: Ciphersuites,
    nb_key_package: Option<u32>,
) -> CoreCryptoResult<CoreCrypto> {
    CoreCrypto::new(path, key, Some(client_id), Some(ciphersuites), nb_key_package).await
}
