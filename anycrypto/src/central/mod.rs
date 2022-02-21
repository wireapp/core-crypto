// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

mod config;
use openmls::prelude::{TlsSerializeTrait, TlsSizeTrait};

pub use self::config::*;

use std::collections::HashMap;

pub type ConversationId = uuid::Uuid;

// #[derive(Debug)]
// pub enum ClientIdentity {
//     Mls(openmls::key_packages::KeyPackageBundle),
//     Proteus(proteus::keys::IdentityKeyPair),
// }

// #[derive(Debug)]
// pub struct Client {
//     protocol_in_use: crate::Protocol,
//     keys: ClientIdentity,
// }

/// Central acts as an abstraction over both MLS Groups and Proteus Sessions.
/// The goal being to create a superset API for both that makes functionally similar operations behave the same.
/// For instance: creating a new conversation for example creates a new `Group` in MLS, and sum(users' devices) `Session`s in Proteus
#[derive(Debug)]
pub struct Central {
    mls_backend: mls_crypto_provider::MlsCryptoProvider,
    mls_groups: HashMap<ConversationId, openmls::group::MlsGroup>,
    proteus:
        HashMap<ConversationId, Vec<proteus::session::Session<proteus::keys::IdentityKeyPair>>>,
}

impl Central {
    pub fn try_new<S: AsRef<str>>(
        store_path: S,
        identity_key: S,
    ) -> crate::error::CryptoResult<Self> {
        let mls_backend =
            mls_crypto_provider::MlsCryptoProvider::try_new(store_path, identity_key)?;

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
                    &self.mls_backend,
                    &mls_config,
                    openmls::group::GroupId::from_slice(id.as_bytes()),
                    &[],
                ).map_err(crate::MlsError::from)?;
                self.mls_groups.insert(id, group);
            }
            crate::Protocol::Proteus => {
                let proteus_config: ProteusConversationConfiguration = config.try_into()?;
                let session = proteus::session::Session::init_from_prekey(
                    proteus_config.identity,
                    proteus_config.prekeys,
                ).map_err(crate::ProteusError::from)?;
                // TODO: Should we create N sessions for each device? or we do that later?
                self.proteus.insert(id, vec![session]);
            }
        }

        Ok(())
    }

    pub fn encrypt_message<M: AsRef<[u8]>>(
        &mut self,
        protocol: crate::Protocol,
        conversation: ConversationId,
        message: M,
    ) -> crate::error::CryptoResult<Vec<u8>> {
        match protocol {
            crate::Protocol::Mls => {
                let group = self.mls_groups
                    .get_mut(&conversation)
                    .ok_or(crate::error::CryptoError::ConversationNotFound {
                        protocol,
                        conversation
                    })?;

                let message = group.create_message(&self.mls_backend, message.as_ref()).map_err(crate::MlsError::from)?;
                let mut buf = Vec::with_capacity(message.tls_serialized_len());
                // FIXME: Support error
                // TODO: Define serialization format? Probably won't be the TLS thingy?
                message.tls_serialize(&mut buf).unwrap();
                Ok(buf)
            },
            crate::Protocol::Proteus => {
                let sessions = self.proteus
                    .get_mut(&conversation)
                    .ok_or(crate::error::CryptoError::ConversationNotFound {
                        protocol,
                        conversation
                    })?;

                let envelopes = sessions.iter_mut()
                    .try_fold(
                        std::collections::HashMap::new(),
                        |mut acc, session| -> crate::CryptoResult<BatchedMessage> {
                            let identity = session.remote_identity().fingerprint();
                            let message = session.encrypt(message.as_ref()).map_err(crate::ProteusError::from)?;
                            acc.insert(identity, message);
                            Ok(acc)
                        }
                    )?;

                // TODO: ser BatchedMessage to CBOR? Addendum to proteus protocol?
                todo!()
            }
        }
    }

    pub fn decrypt_message<M: AsRef<[u8]>>(
        &mut self,
        protocol: crate::Protocol,
        conversation: ConversationId,
        message: M,
    ) -> crate::CryptoResult<Vec<u8>> {
        match protocol {
            crate::Protocol::Mls => {
                let group = self.mls_groups
                    .get_mut(&conversation)
                    .ok_or(crate::error::CryptoError::ConversationNotFound {
                        protocol,
                        conversation
                    })?;

                //let

                let parsed_message = group.parse_message(message.as_ref().into(), &self.mls_backend)?;
                let message = group.process_unverified_message(parsed_message, None, &self.mls_backend)?;

                todo!()
            },
            crate::Protocol::Proteus => todo!(),
        }
    }
}

type BatchedMessage<'a> = std::collections::HashMap<String, proteus::message::Envelope<'a>>;

#[cfg(test)]
mod tests {}
