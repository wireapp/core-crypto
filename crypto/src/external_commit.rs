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

use core_crypto_keystore::CryptoKeystoreMls;
use openmls::{
    group::{GroupId, MlsGroup},
    prelude::{MlsMessageOut, PublicGroupState, VerifiablePublicGroupState},
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    prelude::{MlsConversation, MlsConversationConfiguration},
    CryptoError, CryptoResult, MlsCentral, MlsError,
};

impl MlsCentral {
    pub fn join_by_external_commit(
        &self,
        group_state: VerifiablePublicGroupState,
    ) -> CryptoResult<(GroupId, MlsMessageOut)> {
        let credentials = self.mls_client.credentials();
        let (mut group, message) = MlsGroup::join_by_external_commit(
            &self.mls_backend,
            None,
            group_state,
            &MlsConversationConfiguration::openmls_default_configuration(),
            &[],
            credentials,
        )
        .map_err(MlsError::from)
        .map_err(CryptoError::from)?;
        let mut buf = vec![];
        group.save(&mut buf)?;
        self.mls_backend
            .key_store()
            .mls_pending_groups_save(group.group_id().as_slice(), &buf)
            .map_err(CryptoError::from)?;
        Ok((group.group_id().clone(), message))
    }

    pub fn export_group_state(&self, group_id: &[u8]) -> CryptoResult<PublicGroupState> {
        let state = self
            .mls_backend
            .key_store()
            .mls_groups_get(group_id)
            .map_err(CryptoError::from)?;
        let group = MlsGroup::load(&mut &state[..])?;
        group
            .export_public_group_state(&self.mls_backend)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub fn merge_pending_group_from_external_commit(
        &mut self,
        group_id: &[u8],
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<MlsConversation> {
        let buf = self
            .mls_backend
            .key_store()
            .mls_pending_groups_load(group_id)
            .map_err(CryptoError::from)?;
        let mut mls_group = MlsGroup::load(&mut &buf[..])?;
        mls_group.merge_pending_commit().map_err(MlsError::from)?;
        self.mls_backend
            .key_store()
            .mls_pending_groups_delete(group_id)
            .map_err(CryptoError::from)?;
        MlsConversation::from_mls_group(mls_group, configuration, &self.mls_backend)
    }
}
