use mls_rs_codec::{MlsDecode as _, MlsEncode as _};
use mls_rs_core::psk::PreSharedKey as MlsRsPsk;
use zeroize::ZeroizeOnDrop;

use core_crypto_macros::Entity;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

#[derive(Clone, Debug, PartialEq, Eq, Entity, serde::Serialize, serde::Deserialize, ZeroizeOnDrop)]
pub struct Psk {
    pub id: Vec<u8>,
    pub data: Vec<u8>,
}

impl TryFrom<(Vec<u8>, MlsRsPsk)> for Psk {
    type Error = CryptoKeystoreError;

    fn try_from(value: (Vec<u8>, MlsRsPsk)) -> CryptoKeystoreResult<Self> {
        let keystore_instance = Self {
            id: value.0,
            data: value.1.mls_encode_to_vec()?,
        };

        Ok(keystore_instance)
    }
}

impl TryFrom<Psk> for (Vec<u8>, MlsRsPsk) {
    type Error = CryptoKeystoreError;

    fn try_from(value: Psk) -> CryptoKeystoreResult<Self> {
        let mls_rs_instance = (value.id.clone(), MlsRsPsk::mls_decode(&mut value.data.as_slice())?);
        Ok(mls_rs_instance)
    }
}
