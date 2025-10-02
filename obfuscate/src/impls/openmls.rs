use std::fmt::Formatter;

use openmls::{
    credentials::Certificate,
    prelude::{
        BasicCredential, Credential, KeyPackageSecretEncapsulation, Member, MlsCredentialType, Proposal,
        QueuedProposal, Sender,
    },
};

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

impl Obfuscate for Member {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Member { ")?;
        write!(f, "index: {:?}", self.index)?;
        f.write_str(", credential: ")?;
        self.credential.obfuscate(f)?;
        f.write_str(" }")
    }
}

impl Obfuscate for Credential {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.mls_credential().obfuscate(f)
    }
}

impl Obfuscate for BasicCredential {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BasicCredential( {} )",
            hex::encode(compute_hash(format!("{:?}", self).as_bytes())).as_str()
        )
    }
}

impl Obfuscate for Certificate {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("Certificate( ")?;
        self.identity.obfuscate(f)?;
        f.write_str(")")
    }
}

impl Obfuscate for MlsCredentialType {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            MlsCredentialType::Basic(basic_credential) => basic_credential.obfuscate(f),
            MlsCredentialType::X509(identity_cert) => identity_cert.obfuscate(f),
        }
    }
}
