use std::fmt::Formatter;

use openmls::prelude::{KeyPackageSecretEncapsulation, Proposal, QueuedProposal, Sender};

use crate::Obfuscate;

impl Obfuscate for Proposal {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Proposal::Add(_) => "Add",
            Proposal::Update(_) => "Update",
            Proposal::Remove(_) => "Remove",
            Proposal::PreSharedKey(_) => "PreSharedKey",
            Proposal::ReInit(_) => "ReInit",
            Proposal::ExternalInit(_) => "ExternalInit",
            Proposal::AppAck(_) => "AppAck",
            Proposal::GroupContextExtensions(_) => "GroupContextExtensions",
        })
    }
}

impl Obfuscate for KeyPackageSecretEncapsulation {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("<secret>")
    }
}

impl Obfuscate for QueuedProposal {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.proposal.obfuscate(f)
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
