uniffi_macros::include_scaffolding!("CoreCrypto");

use core_crypto::prelude::*;

#[derive(Debug, Clone)]
pub struct CoreCrypto(std::sync::Arc<std::sync::RwLock<MlsCentral>>);

fn init_corecrypto_with_path_and_key(path: String, key: String) -> CryptoResult<CoreCrypto> {
    let central = MlsCentral::try_new(path, key)?;
    Ok(CoreCrypto(std::sync::Arc::new(std::sync::RwLock::new(central))))
}

// fn register_on_welcome_cb(cc: &CoreCrypto, cb: fn(Vec<u8>)) {
//     todo!()
// }

// impl UniffiCustomTypeConverter for identifiers::QualifiedUuid {}
