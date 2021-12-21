mod config;
pub use self::config::*;

use std::collections::HashMap;

pub type ConversationId = uuid::Uuid;


/// Central acts as an abstraction over both MLS Groups and Proteus Sessions.
/// The goal being to create a superset API for both that makes functionally similar operations behave the same.
/// For instance: creating a new conversation for example creates a new `Group` in MLS, and sum(users' devices) `Session`s in Proteus
#[derive(Debug)]
pub struct Central  {
    mls_backend: crate::mls_crypto_provider::MlsCryptoProvider,
    mls_groups: HashMap<ConversationId, openmls::group::MlsGroup>,
    proteus: HashMap<ConversationId, Vec<proteus::session::Session<proteus::keys::IdentityKeyPair>>>,
}

impl Central {
    pub fn try_new<S: AsRef<str>>(store_path: S, identity_key: S) -> crate::error::CryptoResult<Self> {
        let mls_backend = crate::mls_crypto_provider::MlsCryptoProvider::try_new(store_path, identity_key)?;

        Ok(Self {
            mls_backend,
            mls_groups: Default::default(),
            proteus: Default::default(),
        })
    }
    /// Create a new (empty) conversation
    pub fn new_conversation(
        &mut self,
        protocol: crate::Protocol,
        id: ConversationId,
        config: ConversationConfiguration,
    ) -> crate::error::CryptoResult<()> {
        match protocol {
            crate::Protocol::Mls => {
                let mls_config = config.try_into()?;
                let group = openmls::group::MlsGroup::new(
                    &mut self.mls_backend,
                    &mls_config,
                    openmls::group::GroupId::from_slice(id.as_bytes()),
                    &[]
                )?;
                self.mls_groups.insert(id, group);
            },
            crate::Protocol::Proteus => {
                let proteus_config: ProteusConversationConfiguration = config.try_into()?;
                let session = proteus::session::Session::init_from_prekey(
                    proteus_config.identity,
                    proteus_config.prekeys
                )?;
                // TODO: Should we create N sessions for each device? or we do that later?
                self.proteus.insert(id, vec![session]);
            },
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

}
