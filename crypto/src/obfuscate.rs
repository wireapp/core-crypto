use crate::prelude::{ClientId, ConversationId};
use derive_more::{Constructor, From};
use hex;
use log::kv::{ToValue, Value};
use openmls::framing::Sender;
use openmls::group::QueuedProposal;
use openmls::prelude::Proposal;
use sha2::{Digest, Sha256};
use std::fmt::{Debug, Formatter};

pub(crate) trait Obfuscate {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result;
}

impl Obfuscate for &ConversationId {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}

impl Obfuscate for &ClientId {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str(hex::encode(compute_hash(self)).as_str())
    }
}

impl Obfuscate for &Proposal {
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

impl Obfuscate for &QueuedProposal {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        (&self.proposal).obfuscate(f)
    }
}

impl Obfuscate for &Sender {
    fn obfuscate(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Sender::Member(leaf_node_index) => write!(f, "Member{leaf_node_index}"),
            Sender::External(external_sender_index) => write!(f, "External{external_sender_index:?}"),
            Sender::NewMemberProposal => write!(f, "NewMemberProposal"),
            Sender::NewMemberCommit => write!(f, "NewMemberCommit"),
        }
    }
}

#[derive(From, Constructor)]
pub(crate) struct Obfuscated<T>(T);

impl<T> Debug for Obfuscated<T>
where
    T: Obfuscate,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.0.obfuscate(f)
    }
}

impl<T> ToValue for Obfuscated<T>
where
    T: Obfuscate,
{
    fn to_value(&self) -> Value {
        Value::from_debug(self)
    }
}

fn compute_hash(bytes: &[u8]) -> [u8; 10] {
    let mut hasher = Sha256::new();
    let mut output = [0; 10];
    hasher.update(bytes);
    output.copy_from_slice(&hasher.finalize().as_slice()[0..10]);
    output
}
