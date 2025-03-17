#[derive(Debug, Clone, Eq, Hash, PartialEq, derive_more::From)]
pub struct ClientId(pub(crate) core_crypto::prelude::ClientId);

#[cfg(not(target_family = "wasm"))]
uniffi::custom_type!(ClientId, Vec<u8>, {
    lower: |id| id.0.to_vec(),
    try_lift: |vec| Ok(Self(vec.into()))
});

pub type FfiClientId = Box<[u8]>;
