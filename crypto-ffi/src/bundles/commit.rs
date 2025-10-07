use core_crypto::MlsCommitBundle;

use crate::{
    CoreCryptoError, GroupInfoBundle,
    core_crypto_context::mls::{WelcomeMaybeArc, welcome_coerce_maybe_arc},
};

/// Information returned when a commit is created.
#[derive(uniffi::Record)]
pub struct CommitBundle {
    /// A welcome message if there are pending Add proposals
    pub welcome: Option<WelcomeMaybeArc>,
    /// The commit message
    pub commit: Vec<u8>,
    /// `GroupInfo` if the commit is merged
    pub group_info: GroupInfoBundle,
    /// An encrypted message to fan out to all other conversation members in the new epoch
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
