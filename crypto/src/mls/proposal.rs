use crate::mls::ClientId;
use openmls::prelude::{KeyPackage, hash_ref::ProposalRef};

/// Abstraction over a [openmls::prelude::hash_ref::ProposalRef] to deal with conversions
#[derive(Debug, Clone, Eq, PartialEq, derive_more::From, derive_more::Deref, derive_more::Display)]
pub struct MlsProposalRef(ProposalRef);

impl From<Vec<u8>> for MlsProposalRef {
    fn from(value: Vec<u8>) -> Self {
        Self(ProposalRef::from_slice(value.as_slice()))
    }
}

impl MlsProposalRef {
    /// Duh
    pub fn into_inner(self) -> ProposalRef {
        self.0
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.as_slice().to_vec()
    }
}

#[cfg(test)]
impl From<MlsProposalRef> for Vec<u8> {
    fn from(prop_ref: MlsProposalRef) -> Self {
        prop_ref.0.as_slice().to_vec()
    }
}

/// Internal representation of proposal to ease further additions
// To solve the clippy issue we'd need to box the `KeyPackage`, but we can't because we need an
// owned value of it. We can have it when Box::into_inner is stablized.
// https://github.com/rust-lang/rust/issues/80437
#[allow(clippy::large_enum_variant)]
pub enum MlsProposal {
    /// Requests that a client with a specified KeyPackage be added to the group
    Add(KeyPackage),
    /// Similar mechanism to Add with the distinction that it replaces
    /// the sender's LeafNode in the tree instead of adding a new leaf to the tree
    Update,
    /// Requests that the member with LeafNodeRef removed be removed from the group
    Remove(ClientId),
}
