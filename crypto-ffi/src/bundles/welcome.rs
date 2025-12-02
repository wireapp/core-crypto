use std::sync::Arc;

use crate::{ConversationId, crl::NewCrlDistributionPoints};

/// see [core_crypto::WelcomeBundle]
#[derive(Debug, uniffi::Record)]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    pub id: Arc<ConversationId>,
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
        let crl_new_distribution_points = crl_new_distribution_points.into();
        let id = Arc::new(id.into());
        Self {
            id,
            crl_new_distribution_points,
        }
    }
}
