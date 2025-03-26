use zeroize::Zeroize;

use crate::connection::FetchFromDatabase;

#[derive(Debug, Clone, Zeroize, PartialEq, Eq)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ProteusIdentity {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

impl ProteusIdentity {
    pub const SK_KEY_SIZE: usize = 64;
    pub const PK_KEY_SIZE: usize = 32;

    pub fn sk_raw(&self) -> zeroize::Zeroizing<[u8; Self::SK_KEY_SIZE]> {
        let mut slice = zeroize::Zeroizing::new([0u8; Self::SK_KEY_SIZE]);
        debug_assert_eq!(self.sk.len(), Self::SK_KEY_SIZE);
        slice.copy_from_slice(&self.sk[..Self::SK_KEY_SIZE]);
        slice
    }

    pub fn pk_raw(&self) -> zeroize::Zeroizing<[u8; Self::PK_KEY_SIZE]> {
        let mut slice = zeroize::Zeroizing::new([0u8; Self::PK_KEY_SIZE]);
        debug_assert_eq!(self.pk.len(), Self::PK_KEY_SIZE);
        slice.copy_from_slice(&self.pk[..Self::PK_KEY_SIZE]);
        slice
    }
}

#[derive(Debug, Clone, Zeroize, PartialEq, Eq)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ProteusPrekey {
    pub id: u16,
    id_bytes: Vec<u8>,
    pub prekey: Vec<u8>,
}

impl ProteusPrekey {
    pub fn from_raw(id: u16, prekey: Vec<u8>) -> Self {
        Self {
            id_bytes: id.to_le_bytes().into(),
            id,
            prekey,
        }
    }

    pub fn id_bytes(&self) -> &[u8] {
        &self.id_bytes
    }

    pub fn id_from_slice(slice: &[u8]) -> u16 {
        if slice.len() < 2 {
            panic!("Oops, Proteus Prekey id slice is too small!");
        }

        let mut id_buf = [0u8; 2];
        id_buf.copy_from_slice(&slice[..2]);
        let id: u16 = u16::from_le_bytes(id_buf);
        id
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
        self.id_bytes = self.id.to_le_bytes().into();
    }

    pub async fn get_free_id(conn: &crate::Connection) -> crate::CryptoKeystoreResult<u16> {
        let mut id = 1u16;
        let limit = u16::MAX;
        while id <= limit {
            if id == limit {
                return Err(crate::CryptoKeystoreError::NoFreePrekeyId);
            }
            if conn.find::<Self>(&id.to_le_bytes()).await?.is_none() {
                break;
            }
            id += 1;
        }

        Ok(id)
    }
}

#[derive(Debug, Clone, Zeroize, PartialEq, Eq, core_crypto_macros::Entity)]
#[zeroize(drop)]
#[cfg_attr(
    any(target_family = "wasm", feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct ProteusSession {
    pub id: String,
    pub session: Vec<u8>,
}
