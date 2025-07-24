use mls_rs_core::group::GroupState as MlsRsGroup;
use zeroize::ZeroizeOnDrop;

use core_crypto_macros::Entity;

// TODO(SimonThormeyer): instead of deriving `Entity`, implement it manually to allow the ON DELETE CASCADE logic in wasm
#[derive(Clone, Debug, PartialEq, Eq, Entity, serde::Serialize, serde::Deserialize, ZeroizeOnDrop)]
pub struct Group {
    pub id: Vec<u8>,
    pub snapshot: Vec<u8>,
}

impl From<MlsRsGroup> for Group {
    fn from(value: MlsRsGroup) -> Self {
        Self {
            id: value.id,
            snapshot: value.data,
        }
    }
}

impl From<Group> for MlsRsGroup {
    fn from(value: Group) -> Self {
        Self {
            id: value.id.clone(),
            data: value.snapshot.clone(),
        }
    }
}
