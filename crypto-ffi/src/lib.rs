uniffi_macros::include_scaffolding!("CoreCrypto");

pub use core_crypto::prelude::*;

pub struct ConversationConfiguration {
    pub author: UserId,
    pub extra_members: Vec<UserId>,
    pub admins: Vec<UserId>,
    pub ciphersuite: Option<String>,
    pub key_rotation_span: Option<std::time::Duration>,
}

#[derive(Debug)]
pub struct ConversationCreationMessage {
    pub welcome: Vec<u8>,
    pub message: Vec<u8>,
}

impl UniffiCustomTypeWrapper for identifiers::QualifiedUuid {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}

impl UniffiCustomTypeWrapper for identifiers::ZeroKnowledgeUuid {
    type Wrapped = String;

    fn wrap(val: Self::Wrapped) -> uniffi::Result<Self>
    where
        Self: Sized,
    {
        Ok(val.parse()?)
    }

    fn unwrap(obj: Self) -> Self::Wrapped {
        obj.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CoreCrypto(std::sync::Arc<std::sync::RwLock<MlsCentral>>);

fn init_corecrypto_with_path_and_key(path: String, key: String) -> CryptoResult<CoreCrypto> {
    let central = MlsCentral::try_new(path, key)?;
    Ok(CoreCrypto(std::sync::Arc::new(std::sync::RwLock::new(central))))
}

// fn register_on_welcome_cb(cc: &CoreCrypto, cb: fn(Vec<u8>)) {
//     todo!()
// }
