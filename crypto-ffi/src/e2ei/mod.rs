/// The end-to-end identity verification state of a conversation.
///
/// Note: this does not check pending state (pending commit, pending proposals), so it does not
/// consider members about to be added or removed.
#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate.
    Verified = 1,
    /// Some clients are either still using Basic credentials or their certificate has expired.
    NotVerified,
    /// All clients are still using Basic credentials.
    ///
    /// Note: if all clients have expired certificates, `NotVerified` is returned instead.
    NotEnabled,
}

impl From<core_crypto::E2eiConversationState> for E2eiConversationState {
    fn from(value: core_crypto::E2eiConversationState) -> Self {
        match value {
            core_crypto::E2eiConversationState::Verified => Self::Verified,
            core_crypto::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}
