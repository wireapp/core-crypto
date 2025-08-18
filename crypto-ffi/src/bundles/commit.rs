use core_crypto::prelude::MlsCommitBundle;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    CoreCryptoError, GroupInfoBundle,
    core_crypto_context::mls::{WelcomeMaybeArc, welcome_coerce_maybe_arc},
};

/// Information returned when a commit is created.
#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct CommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<WelcomeMaybeArc>,
    /// The commit message
    pub commit: Vec<u8>,
    /// `GroupInfo` if the commit is merged
    pub group_info: GroupInfoBundle,
    /// An encrypted message to fan out to all other conversation members in the new epoch
    #[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = "encryptedMessage", readonly))]
    pub encrypted_message: Option<Vec<u8>>,
}

impl TryFrom<MlsCommitBundle> for CommitBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsCommitBundle) -> Result<Self, Self::Error> {
        let encrypted_message = msg.encrypted_message.clone();
        let (welcome, commit, group_info) = msg.to_bytes_triple()?;
        let welcome = welcome.map(welcome_coerce_maybe_arc);
        let group_info = group_info.into();
        Ok(Self {
            welcome,
            commit,
            group_info,
            encrypted_message,
        })
    }
}
