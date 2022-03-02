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


#[repr(C)]
#[derive(Debug)]
pub struct MlsConversationConfiguration {
    pub(crate) init_keys: Vec<Vec<u8>>,
    pub(crate) admins: Vec<uuid::Uuid>,
    // FIXME: No way to configure ciphersuites.
    // FIXME: Can maybe only check it against the supported ciphersuites in the group afterwards?
    pub(crate) ciphersuite: (),
    // FIXME: openmls::group::config::UpdatePolicy is NOT configurable at the moment.
    // FIXME: None of the fields are available and there are no way to build it/mutate it
    pub(crate) key_rotation_span: (),
}

#[repr(C)]
#[derive(Debug)]
pub struct ProteusConversationConfiguration {
    pub(crate) identity: proteus::keys::IdentityKeyPair,
    pub(crate) prekeys: proteus::keys::PreKeyBundle,
}

#[repr(C)]
#[derive(Debug)]
pub enum ConversationConfiguration {
    Mls(Box<MlsConversationConfiguration>),
    Proteus(Box<ProteusConversationConfiguration>),
}

impl TryInto<MlsConversationConfiguration> for ConversationConfiguration {
    type Error = crate::CryptoError;

    fn try_into(self) -> Result<MlsConversationConfiguration, Self::Error> {
        match self {
            ConversationConfiguration::Mls(mls_config) => Ok(*mls_config),
            _ => Err(crate::CryptoError::ConfigurationMismatch(
                crate::Protocol::Proteus,
            )),
        }
    }
}

impl TryInto<ProteusConversationConfiguration> for ConversationConfiguration {
    type Error = crate::CryptoError;

    fn try_into(self) -> Result<ProteusConversationConfiguration, Self::Error> {
        match self {
            ConversationConfiguration::Proteus(proteus_config) => Ok(*proteus_config),
            _ => Err(crate::CryptoError::ConfigurationMismatch(
                crate::Protocol::Mls,
            )),
        }
    }
}

impl TryInto<openmls::group::MlsGroupConfig> for ConversationConfiguration {
    type Error = crate::CryptoError;

    fn try_into(self) -> Result<openmls::group::MlsGroupConfig, Self::Error> {
        let mls_config: MlsConversationConfiguration = self.try_into()?;
        let mls_group_config = openmls::group::MlsGroupConfig::builder()
            .wire_format(openmls::framing::WireFormat::MlsCiphertext)
            // .update_policy() FIXME: Unsupported
            // .padding_size(0) TODO: Understand what it does and define a safe value
            // .max_past_epochs(5) TODO: Understand what it does and define a safe value
            // .number_of_resumtion_secrets(0) TODO: Understand what it does and define a safe value
            // .use_ratchet_tree_extension(false) TODO: Understand what it does and define a safe value
            .build();

        Ok(mls_group_config)
    }
}
