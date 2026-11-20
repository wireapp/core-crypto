use std::fmt::Formatter;

use openmls::prelude::{Credential, Member, Proposal, QueuedProposal, Sender};

use crate::{Obfuscate, compute_hash};

impl Obfuscate for Proposal {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Proposal::Add(_) => "Add",
            Proposal::Update(_) => "Update",
            Proposal::Remove(_) => "Remove",
            Proposal::PreSharedKey(_) => "PreSharedKey",
            Proposal::ReInit(_) => "ReInit",
            Proposal::ExternalInit(_) => "ExternalInit",
            Proposal::GroupContextExtensions(_) => "GroupContextExtensions",
            Proposal::SelfRemove => "SelfRemove",
            Proposal::Custom(_) => "Custom",
        })
    }
}

impl Obfuscate for QueuedProposal {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.proposal().obfuscate(f)
    }
}

impl Obfuscate for Sender {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Sender::Member(leaf_node_index) => write!(f, "Member{leaf_node_index}"),
            Sender::External(external_sender_index) => write!(f, "External{external_sender_index:?}"),
            Sender::NewMemberProposal => write!(f, "NewMemberProposal"),
            Sender::NewMemberCommit => write!(f, "NewMemberCommit"),
        }
    }
}

impl Obfuscate for Member {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Member { ")?;
        write!(f, "index: {:?}", self.index)?;
        f.write_str(", credential: ")?;
        self.credential.obfuscate(f)?;
        f.write_str(" }")
    }
}

/// openmls keeps a credential's content as opaque bytes, so this hashes them whatever the credential's type.
impl Obfuscate for Credential {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Credential({:?}, {})",
            self.credential_type(),
            hex::encode(compute_hash(self.serialized_content()))
        )
    }
}
