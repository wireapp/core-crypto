pub(crate) mod acme_challenge;
pub(crate) mod acme_directory;
pub(crate) mod enrollment;
pub(crate) mod new_acme_authz;
pub(crate) mod new_acme_order;

/// Indicates the state of a Conversation regarding end-to-end identity.
///
/// Note: this does not check pending state (pending commit, pending proposals) so it does not
/// consider members about to be added/removed
#[derive(Debug, Copy, Clone, uniffi::Enum)]
#[repr(u8)]
pub enum E2eiConversationState {
    /// All clients have a valid E2EI certificate
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is
    /// returned.
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
