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

use crate::entities::{ProteusPrekey, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
    CryptoKeystoreResult, MissingKeyErrorKind,
};

impl EntityBase for ProteusPrekey {
    type ConnectionType = KeystoreDatabaseConnection;

    fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        conn.storage_mut().insert("proteus_prekeys", &mut [self.clone()])?;

        Ok(())
    }

    fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("proteus_prekeys", id.as_bytes())
    }

    fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("proteus_prekeys")
    }

    fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        conn.storage_mut().delete("proteus_prekeys", &[id.as_bytes()])
    }
}

impl Entity for ProteusPrekey {
    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(js_sys::Number::from(&self.id).into())
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.prekey = Self::encrypt_data(cipher, self.prekey.as_slice())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes::Aes256) -> CryptoKeystoreResult<()> {
        self.prekey = Self::decrypt_data(cipher, self.prekey.as_slice())?;

        Ok(())
    }
}
