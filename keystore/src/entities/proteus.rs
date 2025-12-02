use zeroize::Zeroize;

use crate::connection::FetchFromDatabase;

#[derive(core_crypto_macros::Debug, Clone, Zeroize, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct ProteusIdentity {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

impl ProteusIdentity {
    pub const SK_KEY_SIZE: usize = 64;
    pub const PK_KEY_SIZE: usize = 32;
    pub const ID: &[u8; 1] = b"1";

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

#[derive(core_crypto_macros::Debug, Clone, Zeroize, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct ProteusPrekey {
    pub id: u16,
    id_bytes: Vec<u8>,
    #[sensitive]
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

    #[cfg(target_family = "wasm")]
    pub async fn get_free_id(conn: &crate::Database) -> crate::CryptoKeystoreResult<u16> {
        todo!()
    }

    #[cfg(not(target_family = "wasm"))]
    pub async fn get_free_id(conn: &crate::Database) -> crate::CryptoKeystoreResult<u16> {
        let conn = conn.conn().await?;
        let conn = conn.conn().await;

        let mut statement = conn.prepare_cached("SELECT COALESCE(MAX(id), 0) FROM proteus_prekeys")?;
        let existing_max_id = statement.query_one([], |row| row.get::<_, u16>(0))?;
        Ok(existing_max_id + 1)
    }
}

#[derive(
    core_crypto_macros::Debug,
    Clone,
    Zeroize,
    PartialEq,
    Eq,
    core_crypto_macros::Entity,
    serde::Serialize,
    serde::Deserialize,
)]
#[zeroize(drop)]
pub struct ProteusSession {
    pub id: String,
    pub session: Vec<u8>,
}
