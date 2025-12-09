#[cfg(not(target_family = "wasm"))]
pub(crate) mod generic;
#[cfg(target_family = "wasm")]
pub(crate) mod wasm;

#[cfg(not(target_family = "wasm"))]
pub use self::generic::*;
#[cfg(target_family = "wasm")]
pub use self::wasm::*;
