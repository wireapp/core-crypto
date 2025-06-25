use crate::{ConversationIdMaybeArc, conversation_id_coerce_maybe_arc};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::crl::NewCrlDistributionPoints;

/// see [core_crypto::prelude::WelcomeBundle]
#[derive(Debug)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct WelcomeBundle {
    /// Identifier of the joined conversation
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly))]
    pub id: ConversationIdMaybeArc,
    /// New CRL Distribution of members of this group
    #[cfg_attr(target_family = "wasm", wasm_bindgen(readonly, js_name = crlNewDistributionPoints))]
    pub crl_new_distribution_points: NewCrlDistributionPoints,
}

impl From<core_crypto::prelude::WelcomeBundle> for WelcomeBundle {
    fn from(
        core_crypto::prelude::WelcomeBundle {
            id,
            crl_new_distribution_points,
        }: core_crypto::prelude::WelcomeBundle,
    ) -> Self {
        let id = conversation_id_coerce_maybe_arc(id);
        let crl_new_distribution_points = crl_new_distribution_points.into();
        Self {
            id,
            crl_new_distribution_points,
        }
    }
}
