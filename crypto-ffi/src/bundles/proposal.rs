use core_crypto::prelude::MlsProposalBundle;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::CoreCryptoError;

#[derive(Debug, Clone)]
#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(getter_with_clone),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Record))]
pub struct ProposalBundle {
    /// TLS-serialized MLS proposal that needs to be fanned out to other (existing) members of the conversation
    pub proposal: Vec<u8>,
    /// Unique identifier of a proposal.
    pub proposal_ref: Vec<u8>,
    /// New CRL Distribution of members of this group
    pub crl_new_distribution_points: Option<Vec<String>>,
}

impl TryFrom<MlsProposalBundle> for ProposalBundle {
    type Error = CoreCryptoError;

    fn try_from(msg: MlsProposalBundle) -> Result<Self, Self::Error> {
        let (proposal, proposal_ref, crl_new_distribution_points) = msg.to_bytes()?;
        let crl_new_distribution_points = crl_new_distribution_points.into();
        Ok(Self {
            proposal,
            proposal_ref,
            crl_new_distribution_points,
        })
    }
}
