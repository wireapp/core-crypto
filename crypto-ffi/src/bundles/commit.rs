use core_crypto::prelude::MlsCommitBundle;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCryptoError, GroupInfoBundle};

#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct CommitBundle {
    pub welcome: Option<Vec<u8>>,
    pub commit: Vec<u8>,
    pub group_info: GroupInfoBundle,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        let group_info = group_info.into();
        Ok(Self {
            welcome,
            commit,
            group_info,
        })
    }
}
