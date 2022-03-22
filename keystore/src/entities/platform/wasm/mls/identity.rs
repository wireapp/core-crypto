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

use wasm_bindgen::JsValue;

use crate::entities::{MlsIdentity, MlsIdentityExt, StringEntityId};
use crate::{
    connection::KeystoreDatabaseConnection,
    entities::{Entity, EntityBase},
};
use crate::{CryptoKeystoreResult, MissingKeyErrorKind};

impl EntityBase for MlsIdentity {
    type ConnectionType = KeystoreDatabaseConnection;

    fn to_missing_key_err_kind() -> MissingKeyErrorKind {
        MissingKeyErrorKind::MlsIdentityBundle
    }

    fn save(&self, conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<()> {
        let storage = conn.storage_mut();
        storage.insert("mls_identities", &mut [self.clone()])?;

        Ok(())
    }

    fn find_one(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<Option<Self>> {
        conn.storage().get("mls_identities", id.as_bytes())
    }

    fn find_many(_conn: &mut Self::ConnectionType, _ids: &[StringEntityId]) -> crate::CryptoKeystoreResult<Vec<Self>> {
        unimplemented!("There is only one identity within a keystore, so this won't be implemented")
    }

    fn count(conn: &mut Self::ConnectionType) -> crate::CryptoKeystoreResult<usize> {
        conn.storage().count("mls_identities")
    }

    fn delete(conn: &mut Self::ConnectionType, id: &StringEntityId) -> crate::CryptoKeystoreResult<()> {
        if let Some(entity) = Self::find_one(conn, id)? {
            let _ = conn.storage_mut().delete("mls_identities", &[entity.id.as_bytes()])?;
        }
        Ok(())
    }
}

impl Entity for MlsIdentity {
    fn id(&self) -> CryptoKeystoreResult<wasm_bindgen::JsValue> {
        Ok(JsValue::from_str(&self.id))
    }

    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.signature = Self::encrypt_data(cipher, self.signature.as_slice())?;
        self.credential = Self::encrypt_data(cipher, self.credential.as_slice())?;

        Ok(())
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()> {
        self.signature = Self::decrypt_data(cipher, self.signature.as_slice())?;
        self.credential = Self::decrypt_data(cipher, self.credential.as_slice())?;

        Ok(())
    }
}

impl MlsIdentityExt for MlsIdentity {
    fn find_by_signature(conn: &mut Self::ConnectionType, signature: &[u8]) -> CryptoKeystoreResult<Option<Self>> {
        conn.storage().get_indexed("mls_identities", "signature", signature)
    }
}
