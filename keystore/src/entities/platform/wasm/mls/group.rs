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

use crate::entities::{PersistedMlsGroup, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
};
use crate::{CryptoKeystoreResult, MissingKeyErrorKind};

impl EntityBase for PersistedMlsGroup {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsGroup
    }

    fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();

        storage.insert("mls_groups", &mut [self.clone()])?;

        Ok(())
    }

    fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_groups", id.as_bytes())
    }

    fn find_many(conn: &mut Self::ConnectionType, _ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<Vec<Self>> {
        // Plot twist: we always select ALL the persisted groups. Unsure if we want to make it a real API with selection
        conn.storage().get_all("mls_groups")
    }

    fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_groups")
    }

    fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        let _ = conn.storage_mut().delete("mls_groups", &[id.as_bytes()])?;
        Ok(())
    }
}

impl Entity for PersistedMlsGroup {
    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Uint8Array::from(self.id.as_slice()).into())
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::encrypt_data(cipher, self.state.as_slice())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.state = Self::decrypt_data(cipher, self.state.as_slice())?;

        Ok(())
    }
}
