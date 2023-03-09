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

//! Logic to derive subgroups from an established MLS group without needing new KeyPackages from the members

#![allow(unused_imports, dead_code)]

use crate::prelude::Client;
use mls_crypto_provider::{MlsCryptoProvider, RustCrypto};
use openmls::prelude::{
    CredentialBundle, GroupId, KeyPackage, KeyPackageBundle, MlsGroup, OpenMlsCrypto, OpenMlsRand,
    PreSharedKeyProposal, Proposal, SignatureKeypair,
};
use openmls_traits::OpenMlsCryptoProvider;

use crate::{CryptoResult, MlsError};

use super::MlsConversation;

impl MlsConversation {
    /// WIP subgroup derivation
    pub async fn derive_subgroup(&self, client: &Client, backend: &MlsCryptoProvider) -> CryptoResult<Self> {
        let members = self.group.members();
        let mut derived_kps = Vec::with_capacity(members.len());
        let crypto = backend.crypto();
        for m in members.into_iter() {
            let kp_ref = m.hash_ref(crypto).map_err(MlsError::from)?;
            let kp_credential = m.credential();
            let kp_identity = kp_credential.identity();
            let kp_pk = kp_credential.signature_key();
            let sign_alg = kp_pk.signature_scheme();
            let prk = crypto
                .hkdf_extract(openmls::prelude::HashType::Sha2_512, kp_identity, kp_ref.as_slice())
                .map_err(MlsError::from)?;

            let sk_len = RustCrypto::secret_key_len_for_alg(sign_alg).map_err(MlsError::from)?;

            let sk_bytes = crypto
                .hkdf_expand(openmls::prelude::HashType::Sha2_512, &prk, kp_pk.as_slice(), sk_len)
                .map_err(MlsError::from)?;

            let (sk, pk) = crypto
                .keypair_from_raw_sk(sign_alg, &sk_bytes)
                .map_err(MlsError::from)?;
            let keypair = SignatureKeypair::from_bytes(kp_pk.signature_scheme(), sk, pk);

            let credential_bundle = CredentialBundle::from_parts(kp_identity.into(), keypair);

            derived_kps.push(
                KeyPackageBundle::new(&[m.ciphersuite()], &credential_bundle, backend, m.extensions().to_vec())
                    .map_err(MlsError::from)?,
            );
        }

        let new_group_id_ext: [u8; 16] = backend.rand().random_array()?;
        let mut new_group_id = self.group.group_id().to_vec();
        new_group_id.extend_from_slice(&new_group_id_ext);

        let kp = client.gen_keypackage(backend).await?;
        let self_kp_hash = kp.key_package().hash_ref(crypto).map_err(MlsError::from)?;

        let mut new_group = MlsGroup::new(
            backend,
            &self.configuration.as_openmls_default_configuration()?,
            GroupId::from_slice(&new_group_id),
            self_kp_hash.as_slice(),
        )
        .await
        .map_err(MlsError::from)?;

        let _resumption_secret = self.group.resumption_secret();
        // TODO: Add PSK proposal

        let (_commit, _welcome, _) = new_group
            .add_members(
                backend,
                derived_kps
                    .iter()
                    .map(|kpb| kpb.key_package().clone())
                    .collect::<Vec<KeyPackage>>()
                    .as_slice(),
            )
            .await
            .map_err(MlsError::from)?;

        todo!()
    }
}
