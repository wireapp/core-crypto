use openmls::prelude::{MlsMessageIn, MlsMessageOut};
use tls_codec::{Deserialize as _, Serialize as _};

use super::{Error, Result};

/// A Welcome Message as defined in RFC 9420.
///
/// This type is fallibly parseable from raw bytes.
#[derive(Debug, Clone, derive_more::From, derive_more::Into)]
pub struct WelcomeMessage(pub(crate) MlsMessageIn);

impl TryFrom<&[u8]> for WelcomeMessage {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        MlsMessageIn::tls_deserialize_exact(bytes)
            .map(Self)
            .map_err(Error::tls_deserialize("deserializing welcome message as MlsMessageIn"))
    }
}

impl TryFrom<Vec<u8>> for WelcomeMessage {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl From<MlsMessageOut> for WelcomeMessage {
    fn from(value: MlsMessageOut) -> Self {
        Self(value.into())
    }
}

impl WelcomeMessage {
    /// Serialize this message per the TLS encoding in the spec
    pub fn serialize(&self) -> Result<Vec<u8>> {
        MlsMessageOut::from(self.0.clone())
            .tls_serialize_detached()
            .map_err(Error::tls_serialize("serializing welcome message as MlsMessageOut"))
    }
}
