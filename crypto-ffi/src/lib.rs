#[macro_export]
macro_rules! proteus_impl {
    ($body:block or throw $err_type:ty) => {
        {
        cfg_if::cfg_if! {
            if #[cfg(feature = "proteus")] {
                #[allow(clippy::redundant_closure_call)]
                $body
            } else {
                return <$err_type>::Err(core_crypto::Error::FeatureDisabled("proteus").into());
            }
        }
        }
    };
    ($body:block) => {
        proteus_impl!($body or throw ::std::result::Result<_, _>)
    };
}

cfg_if::cfg_if! {
    if #[cfg(target_family = "wasm")] {
        mod wasm;
        pub use self::wasm::*;
    } else {
        uniffi::setup_scaffolding!("core_crypto_ffi");

        mod generic;
        pub use self::generic::*;
    }
}

#[cfg(doc)]
pub mod bindings;
