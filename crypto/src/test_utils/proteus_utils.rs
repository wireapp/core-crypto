use proteus_wasm::{
    keys::{IdentityKeyPair, PreKey},
    session::Session,
};

use crate::test_utils::Result;

#[derive(Debug, Default)]
pub struct CryptoboxLike {
    pub identity: IdentityKeyPair,
    pub prekeys: PrekeyStore,
    pub sessions: std::collections::HashMap<String, Session<IdentityKeyPair>>,
}

impl CryptoboxLike {
    pub fn init() -> Self {
        let identity = IdentityKeyPair::new();
        Self {
            identity,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub fn fingerprint(&self) -> String {
        self.identity.public_key.fingerprint()
    }

    pub fn new_prekey(&mut self) -> proteus_wasm::keys::PreKeyBundle {
        let prekey_id = ((self.prekeys.len() + 1) % u16::MAX as usize) as u16;
        let prekey = proteus_wasm::keys::PreKey::new(proteus_wasm::keys::PreKeyId::new(prekey_id));
        let prekey_bundle = proteus_wasm::keys::PreKeyBundle::new(self.identity.public_key.clone(), &prekey);
        self.prekeys.push(prekey);
        prekey_bundle
    }

    pub fn init_session_from_prekey_bundle(&mut self, session_id: &str, prekey_bundle_raw: &[u8]) {
        let bob_prekey_bundle = proteus_wasm::keys::PreKeyBundle::deserialise(prekey_bundle_raw).unwrap();
        let session =
            proteus_wasm::session::Session::init_from_prekey::<()>(self.identity.clone(), bob_prekey_bundle).unwrap();

        self.sessions.insert(session_id.to_string(), session);
    }

    pub fn encrypt(&mut self, session_id: &str, plaintext: &[u8]) -> Vec<u8> {
        let session = self.sessions.get_mut(session_id).unwrap();
        session.encrypt(plaintext).unwrap().serialise().unwrap()
    }

    pub async fn decrypt(&mut self, session_id: &str, ciphertext: &[u8]) -> Vec<u8> {
        let envelope = proteus_wasm::message::Envelope::deserialise(ciphertext).unwrap();
        match self.sessions.get_mut(session_id) {
            Some(session) => session.decrypt(&mut self.prekeys, &envelope).await.unwrap(),
            None => {
                let (session, message) = proteus_wasm::session::Session::init_from_message(
                    self.identity.clone(),
                    &mut self.prekeys,
                    &envelope,
                )
                .await
                .unwrap();

                self.sessions.insert(session_id.to_string(), session);

                message
            }
        }
    }

    #[allow(dead_code)]
    pub fn session(&mut self, session_id: &str) -> &mut proteus_wasm::session::Session<IdentityKeyPair> {
        self.sessions.get_mut(session_id).unwrap()
    }
}

#[derive(Debug, Default)]
pub struct PrekeyStore(pub Vec<PreKey>);

impl std::ops::Deref for PrekeyStore {
    type Target = Vec<PreKey>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for PrekeyStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct DummyError(());

impl proteus_traits::ProteusErrorCode for DummyError {
    fn code(&self) -> proteus_traits::ProteusErrorKind {
        proteus_traits::ProteusErrorKind::Unknown
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl proteus_traits::PreKeyStore for PrekeyStore {
    type Error = DummyError;

    async fn prekey(
        &mut self,
        id: proteus_traits::RawPreKeyId,
    ) -> Result<Option<proteus_traits::RawPreKey>, Self::Error> {
        let raw_prekey = self
            .0
            .iter()
            .find(|k| k.key_id.value() == id)
            .map(|prekey| prekey.serialise().unwrap());
        Ok(raw_prekey)
    }

    async fn remove(&mut self, id: proteus_traits::RawPreKeyId) -> Result<(), Self::Error> {
        self.0
            .iter()
            .position(|k| k.key_id.value() == id)
            .map(|ix| self.0.swap_remove(ix));
        Ok(())
    }
}
