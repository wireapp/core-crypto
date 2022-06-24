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

use crate::{ClientId, ConversationId, CryptoError, CryptoResult, MlsCentral, MlsError};
use mls_crypto_provider::MlsCryptoProvider;
use openmls::prelude::{KeyPackage, MlsGroup, MlsMessageOut};
use openmls_traits::OpenMlsCryptoProvider;

/// Internal representation of proposal to ease further additions
pub enum MlsProposal {
    /// Requests that a client with a specified KeyPackage be added to the group
    Add(KeyPackage),
    /// Similar mechanism to Add with the distinction that it replaces
    /// the sender's LeafNode in the tree instead of adding a new leaf to the tree
    Update,
    /// Requests that the member with LeafNodeRef removed be removed from the group
    Remove(ClientId),
}

impl MlsProposal {
    fn create(self, backend: &MlsCryptoProvider, group: &mut MlsGroup) -> CryptoResult<MlsMessageOut> {
        match self {
            MlsProposal::Add(key_package) => group
                .propose_add_member(backend, &key_package)
                .map_err(MlsError::from)
                .map_err(CryptoError::from),
            MlsProposal::Update => group
                .propose_self_update(backend, None)
                .map_err(MlsError::from)
                .map_err(CryptoError::from),
            MlsProposal::Remove(client_id) => group
                .members()
                .into_iter()
                .find(|kp| kp.credential().identity() == client_id.as_slice())
                .ok_or(CryptoError::ClientNotFound(client_id))
                .and_then(|kp| {
                    kp.hash_ref(backend.crypto())
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)
                })
                .and_then(|kpr| {
                    group
                        .propose_remove_member(backend, &kpr)
                        .map_err(MlsError::from)
                        .map_err(CryptoError::from)
                }),
        }
    }
}

impl MlsCentral {
    /// Generic proposal factory
    pub fn new_proposal(&mut self, conversation: ConversationId, proposal: MlsProposal) -> CryptoResult<MlsMessageOut> {
        let conversation = self
            .mls_groups
            .get_mut(&conversation)
            .ok_or(CryptoError::ConversationNotFound(conversation))?;
        let group = &mut conversation.group;

        proposal.create(&self.mls_backend, group)
    }
}
