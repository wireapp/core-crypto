use mls_rs_codec::{MlsDecode as _, MlsEncode as _};
use mls_rs_core::key_package::KeyPackageData as MlsRsKeyPackageData;
use zeroize::ZeroizeOnDrop;

use core_crypto_macros::Entity;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

#[derive(Clone, Debug, PartialEq, Eq, Entity, serde::Serialize, serde::Deserialize, ZeroizeOnDrop)]
#[entity(collection_name = "key_package_data")]
pub struct KeyPackageData {
    #[id(hex)]
    pub id: Vec<u8>,
    pub data: Vec<u8>,
}

impl TryFrom<(Vec<u8>, MlsRsKeyPackageData)> for KeyPackageData {
    type Error = CryptoKeystoreError;

    fn try_from(value: (Vec<u8>, MlsRsKeyPackageData)) -> CryptoKeystoreResult<Self> {
        let keystore_instance = Self {
            id: value.0,
            data: value.1.mls_encode_to_vec()?,
        };

        Ok(keystore_instance)
    }
}

impl TryFrom<KeyPackageData> for (Vec<u8>, MlsRsKeyPackageData) {
    type Error = CryptoKeystoreError;

    fn try_from(value: KeyPackageData) -> CryptoKeystoreResult<Self> {
        let mls_rs_instance = (
            value.id.clone(),
            MlsRsKeyPackageData::mls_decode(&mut value.data.as_slice())?,
        );
        Ok(mls_rs_instance)
    }
}
