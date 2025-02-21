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

use crate::clients::{EmulatedClient, EmulatedClientProtocol, EmulatedClientType, EmulatedProteusClient};
use color_eyre::eyre::{Result, eyre};
use std::cell::Cell;

pub(crate) struct CryptoboxNativeClient {
    client_id: Vec<u8>,
    last_prekey_id: Cell<u16>,
    cbox: Option<cryptobox::CBox<cryptobox::store::file::FileStore>>,
    tempdir: Option<tempfile::TempDir>,
}

impl CryptoboxNativeClient {
    pub(crate) fn new() -> Self {
        let client_id = uuid::Uuid::new_v4().into_bytes().to_vec();
        Self {
            client_id,
            last_prekey_id: Cell::new(0),
            cbox: None,
            tempdir: None,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedClient for CryptoboxNativeClient {
    fn client_name(&self) -> &str {
        "Cryptobox::native"
    }

    fn client_type(&self) -> EmulatedClientType {
        EmulatedClientType::Native
    }

    fn client_id(&self) -> &[u8] {
        &self.client_id
    }

    fn client_protocol(&self) -> EmulatedClientProtocol {
        EmulatedClientProtocol::PROTEUS
    }

    async fn wipe(mut self) -> Result<()> {
        let _ = self.cbox.take();
        if let Some(tempdir) = self.tempdir.take() {
            tempdir.close()?;
        }

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl EmulatedProteusClient for CryptoboxNativeClient {
    async fn init(&mut self) -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        self.cbox = Some(cryptobox::CBox::file_open(tempdir.path())?);
        self.tempdir = Some(tempdir);
        Ok(())
    }

    async fn get_prekey(&self) -> Result<Vec<u8>> {
        let cbox = self.cbox.as_ref().ok_or(eyre!("Cryptobox isn't initialized"))?;
        self.last_prekey_id.replace(self.last_prekey_id.get() + 1);
        let prekey_bundle = cbox.new_prekey(proteus::keys::PreKeyId::new(self.last_prekey_id.get()))?;
        Ok(prekey_bundle.serialise()?)
    }

    async fn session_from_prekey(&self, session_id: &str, prekey: &[u8]) -> Result<()> {
        let cbox = self.cbox.as_ref().ok_or(eyre!("Cryptobox isn't initialized"))?;
        let mut session = cbox.session_from_prekey(session_id.to_string(), prekey)?;
        cbox.session_save(&mut session)?;
        Ok(())
    }

    async fn session_from_message(&self, session_id: &str, message: &[u8]) -> Result<Vec<u8>> {
        let cbox = self.cbox.as_ref().ok_or(eyre!("Cryptobox isn't initialized"))?;
        let (mut session, message) = cbox.session_from_message(session_id.to_string(), message)?;
        cbox.session_save(&mut session)?;
        Ok(message)
    }

    async fn encrypt(&self, session_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cbox = self.cbox.as_ref().ok_or(eyre!("Cryptobox isn't initialized"))?;
        let mut session = cbox
            .session_load(session_id.to_string())?
            .ok_or(eyre!("session not found"))?;
        let encrypted = session.encrypt(plaintext)?;
        cbox.session_save(&mut session)?;
        Ok(encrypted)
    }

    async fn decrypt(&self, session_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cbox = self.cbox.as_ref().ok_or(eyre!("Cryptobox isn't initialized"))?;
        let mut session = cbox
            .session_load(session_id.to_string())?
            .ok_or(eyre!("session not found"))?;
        let decrypted = session.decrypt(ciphertext)?;
        cbox.session_save(&mut session)?;
        Ok(decrypted)
    }

    async fn fingerprint(&self) -> Result<String> {
        self.cbox
            .as_ref()
            .map(|cbox| cbox.fingerprint())
            .ok_or(eyre!("Cryptobox isn't initialized"))
    }
}
