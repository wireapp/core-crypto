use crate::{ConversationIdMaybeArc, conversation_id_coerce_maybe_arc, crl::NewCrlDistributionPoints};

/// see [core_crypto::WelcomeBundle]
#[derive(Debug, uniffi::Record)]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    pub id: ConversationIdMaybeArc,
    /// New CRL Distribution of members of this group
    pub crl_new_distribution_points: NewCrlDistributionPoints,
}

impl From<core_crypto::WelcomeBundle> for WelcomeBundle {
    fn from(
        core_crypto::WelcomeBundle {
            id,
            crl_new_distribution_points,
        }: core_crypto::WelcomeBundle,
    ) -> Self {
        let id = conversation_id_coerce_maybe_arc(id);
        let crl_new_distribution_points = crl_new_distribution_points.into();
        Self {
            id,
            crl_new_distribution_points,
        }
    }
}
