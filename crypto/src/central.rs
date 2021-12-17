use std::collections::HashMap;

pub type ConversationId = uuid::Uuid;

#[repr(C)]
#[derive(Debug)]
pub struct MlsConversationConfiguration {
    init_keys: Vec<Vec<u8>>,
    admins: Vec<uuid::Uuid>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    ciphersuite: (),
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no way to build it/mutate it
    key_rotation_span: (),
}

#[repr(C)]
#[derive(Debug)]
pub struct ProteusConversationConfiguration {
    prekeys: proteus::keys::PreKeyBundle,
}

#[repr(C)]
#[derive(Debug)]
pub enum ConversationConfiguration {
    Mls(MlsConversationConfiguration),
    Proteus(ProteusConversationConfiguration),
}

/// Central acts as an abstraction over both MLS Groups and Proteus Sessions.
/// The goal being to create a superset API for both that makes functionally similar operations behave the same.
/// For instance: creating a new conversation for example creates a new `Group` in MLS, and sum(users' devices) `Session`s in Proteus
#[derive(Debug, Default)]
pub struct Central<I>  {
    mls_groups: HashMap<ConversationId, openmls::group::ManagedGroup>,
    proteus: HashMap<ConversationId, Vec<proteus::session::Session<I>>>,
}

impl<I> Central<I> {
    /// Create a new (empty) conversation
    pub fn new_conversation(
        &mut self,
        protocol: crate::Protocol,
        id: ConversationId,
        config: ConversationConfiguration,
    ) {
        match protocol {
            crate::Protocol::Mls => {
                //openmls::group::ManagedGroup::new()
                todo!()
            },
            crate::Protocol::Proteus => todo!(),
        }
    }
}

#[cfg(test)]
mod tests {

}
