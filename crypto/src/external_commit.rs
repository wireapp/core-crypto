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

use openmls::{
    group::{MlsGroup, MlsGroupConfig},
    prelude::{MlsMessageOut, Node, VerifiablePublicGroupState},
};

use crate::{
    prelude::{MlsConversation, MlsConversationConfiguration},
    CryptoError, CryptoResult, MlsCentral, MlsError,
};

impl MlsCentral {
    pub fn join_by_external_commit(
        &self,
        tree_option: Option<&[Option<Node>]>,
        group_state: VerifiablePublicGroupState,
        config: MlsGroupConfig,
        aad: &[u8],
    ) -> CryptoResult<(MlsGroup, MlsMessageOut)> {
        let credentials = self.mls_client.credentials();
        MlsGroup::join_by_external_commit(&self.mls_backend, tree_option, group_state, &config, aad, credentials)
            .map_err(MlsError::from)
            .map_err(CryptoError::from)
    }

    pub fn merge_pending_group_from_external_commit(
        &mut self,
        mut mls_group: MlsGroup,
        configuration: MlsConversationConfiguration,
    ) -> CryptoResult<MlsConversation> {
        mls_group.merge_pending_commit().map_err(MlsError::from)?;
        MlsConversation::from_mls_group(mls_group, configuration, &self.mls_backend)
    }
}
