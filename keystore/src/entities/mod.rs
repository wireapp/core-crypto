#[cfg(feature = "dummy-entity")]
pub mod dummy_entity;
pub(crate) mod general;
pub(crate) mod mls;
#[cfg(feature = "proteus-keystore")]
pub(crate) mod proteus;

mod platform {
    #[cfg(not(target_family = "wasm"))]
    mod generic;
    #[cfg(target_family = "wasm")]
    mod wasm;

    #[cfg(not(target_family = "wasm"))]
    pub use self::generic::*;
    #[cfg(target_family = "wasm")]
    pub use self::wasm::*;
}

#[cfg(feature = "dummy-entity")]
pub use self::dummy_entity::{DummyStoreValue, DummyValue};
#[cfg(feature = "proteus-keystore")]
pub use self::proteus::*;
pub use self::{general::*, mls::*, platform::*};
