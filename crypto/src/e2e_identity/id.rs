use crate::{prelude::ClientId, CryptoError, CryptoResult};
use base64::Engine;

#[cfg(test)]
const DOMAIN: &str = "wire.com";
const COLON: u8 = 58;

/// This format: 'bd4c7053-1c5a-4020-9559-cd7bf7961954:4959bc6ab12f2846@wire.com'
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct WireQualifiedClientId(ClientId);

#[cfg(test)]
impl WireQualifiedClientId {
    pub fn get_user_id(&self) -> String {
        let mut split = self.0.split(|b| b == &COLON);
        let user_id = split.next().unwrap();
        uuid::Uuid::try_parse_ascii(user_id).unwrap().to_string()
    }

    pub fn generate() -> Self {
        let user_id = uuid::Uuid::new_v4().to_string();
        let device_id = rand::random::<u64>();
        let client_id = format!("{user_id}:{device_id:x}@{DOMAIN}");
        Self(client_id.into_bytes().into())
    }
}

/// e.g. from 'vUxwUxxaQCCVWc1795YZVA:4959bc6ab12f2846@wire.com'
impl<'a> TryFrom<&'a [u8]> for WireQualifiedClientId {
    type Error = CryptoError;

    fn try_from(bytes: &'a [u8]) -> CryptoResult<Self> {
        const COLON: u8 = 58;
        let mut split = bytes.split(|b| b == &COLON);
        let user_id = split.next().ok_or(CryptoError::InvalidClientId)?;

        let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(user_id)
            .map_err(|_| CryptoError::InvalidClientId)?;

        let user_id = uuid::Uuid::from_slice(&user_id).map_err(|_| CryptoError::InvalidClientId)?;
        let mut buf = [0; uuid::fmt::Hyphenated::LENGTH];
        let user_id = user_id.hyphenated().encode_lower(&mut buf);

        let rest = split.next().ok_or(CryptoError::InvalidClientId)?;
        if split.next().is_some() {
            return Err(CryptoError::InvalidClientId);
        }

        let client_id = [user_id.as_bytes(), &[COLON], rest].concat();
        Ok(Self(client_id.into()))
    }
}

impl std::str::FromStr for WireQualifiedClientId {
    type Err = CryptoError;

    fn from_str(s: &str) -> CryptoResult<Self> {
        s.as_bytes().try_into()
    }
}

impl TryFrom<WireQualifiedClientId> for String {
    type Error = CryptoError;

    fn try_from(id: WireQualifiedClientId) -> CryptoResult<Self> {
        Ok(String::from_utf8(id.to_vec())?)
    }
}

/// This format: 'vUxwUxxaQCCVWc1795YZVA:4959bc6ab12f2846@wire.com'
#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_more::From, derive_more::Into, derive_more::Deref)]
pub struct QualifiedE2eiClientId(ClientId);

#[cfg(test)]
impl QualifiedE2eiClientId {
    pub fn generate() -> Self {
        Self::generate_from_user_id(&uuid::Uuid::new_v4())
    }

    pub fn generate_with_domain(domain: &str) -> Self {
        Self::generate_from_user_id_and_domain(&uuid::Uuid::new_v4(), domain)
    }

    pub fn generate_from_user_id(user_id: &uuid::Uuid) -> Self {
        Self::generate_from_user_id_and_domain(user_id, DOMAIN)
    }

    pub fn generate_from_user_id_and_domain(user_id: &uuid::Uuid, domain: &str) -> Self {
        use base64::Engine as _;

        let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes());

        let device_id = rand::random::<u64>();
        let client_id = format!("{user_id}:{device_id:x}@{domain}");
        Self(client_id.into_bytes().into())
    }

    pub fn from_str_unchecked(s: &str) -> Self {
        Self(s.as_bytes().into())
    }
}

/// e.g. from 'bd4c7053-1c5a-4020-9559-cd7bf7961954:4959bc6ab12f2846@wire.com'
impl<'a> TryFrom<&'a [u8]> for QualifiedE2eiClientId {
    type Error = CryptoError;

    fn try_from(bytes: &'a [u8]) -> CryptoResult<Self> {
        let mut split = bytes.split(|b| b == &COLON);
        let user_id = split.next().ok_or(CryptoError::InvalidClientId)?;

        let user_id = std::str::from_utf8(user_id)?
            .parse::<uuid::Uuid>()
            .map_err(|_| CryptoError::InvalidClientId)?;

        let user_id = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes());

        let rest = split.next().ok_or(CryptoError::InvalidClientId)?;
        if split.next().is_some() {
            return Err(CryptoError::InvalidClientId);
        }

        let client_id = [user_id.as_bytes(), &[COLON], rest].concat();
        Ok(Self(client_id.into()))
    }
}

#[cfg(test)]
impl std::str::FromStr for QualifiedE2eiClientId {
    type Err = CryptoError;

    fn from_str(s: &str) -> CryptoResult<Self> {
        s.as_bytes().try_into()
    }
}

impl TryFrom<QualifiedE2eiClientId> for String {
    type Error = CryptoError;

    fn try_from(id: QualifiedE2eiClientId) -> CryptoResult<Self> {
        Ok(String::from_utf8(id.to_vec())?)
    }
}
