#[cfg(not(target_os = "unknown"))]
pub(crate) mod generic;
#[cfg(target_os = "unknown")]
pub(crate) mod wasm;

#[cfg(not(target_os = "unknown"))]
pub use self::generic::*;
#[cfg(target_os = "unknown")]
pub use self::wasm::*;
