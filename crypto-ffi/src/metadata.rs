#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[inline]
pub fn version() -> String {
    VERSION.to_string()
}

// Unfortunately, we need to define the `BuildMetadata` struct twice:
// not only does it require a different fundamental member type, but
// the `wasm_bindgen` attribute on the struct members is not compatible
// with the `#[cfg_attr]` attribute.

#[cfg(not(target_family = "wasm"))]
#[derive(uniffi::Record)]
/// Metadata describing the conditions of the build of this software.
pub struct BuildMetadata {
    /// Build Timestamp
    pub timestamp: String,
    /// Whether this build was in Debug mode (true) or Release mode (false)
    pub cargo_debug: String,
    /// Features enabled for this build
    pub cargo_features: String,
    /// Optimization level
    pub opt_level: String,
    /// Build target triple
    pub target_triple: String,
    /// Git branch
    pub git_branch: String,
    /// Output of `git describe`
    pub git_describe: String,
    /// Hash of current git commit
    pub git_sha: String,
    /// `true` when the source code differed from the commit at the most recent git hash
    pub git_dirty: String,
}

/// Metadata describing the conditions of the build of this software.
#[cfg(target_family = "wasm")]
#[wasm_bindgen(inspectable)]
pub struct BuildMetadata {
    /// Build Timestamp
    #[wasm_bindgen(readonly)]
    pub timestamp: &'static str,
    /// Whether this build was in Debug mode (true) or Release mode (false)
    #[wasm_bindgen(readonly, js_name = "cargoDebug")]
    pub cargo_debug: &'static str,
    /// Features enabled for this build
    #[wasm_bindgen(readonly, js_name = "cargoFeatures")]
    pub cargo_features: &'static str,
    /// Optimization level
    #[wasm_bindgen(readonly, js_name = "optLevel")]
    pub opt_level: &'static str,
    /// Build target triple
    #[wasm_bindgen(readonly, js_name = "targetTriple")]
    pub target_triple: &'static str,
    /// Git branch
    #[wasm_bindgen(readonly, js_name = "gitBranch")]
    pub git_branch: &'static str,
    /// Output of `git describe`
    #[wasm_bindgen(readonly, js_name = "gitDescribe")]
    pub git_describe: &'static str,
    /// Hash of current git commit
    #[wasm_bindgen(readonly, js_name = "gitSha")]
    pub git_sha: &'static str,
    /// `true` when the source code differed from the commit at the most recent git hash
    #[wasm_bindgen(readonly, js_name = "gitDirty")]
    pub git_dirty: &'static str,
}

/// Returns build data for CoreCrypto
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[inline]
pub fn build_metadata() -> BuildMetadata {
    BuildMetadata {
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        timestamp: core_crypto::BUILD_METADATA.timestamp.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        cargo_debug: core_crypto::BUILD_METADATA.cargo_debug.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        cargo_features: core_crypto::BUILD_METADATA.cargo_features.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        opt_level: core_crypto::BUILD_METADATA.opt_level.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        target_triple: core_crypto::BUILD_METADATA.target_triple.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        git_branch: core_crypto::BUILD_METADATA.git_branch.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        git_describe: core_crypto::BUILD_METADATA.git_describe.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        git_sha: core_crypto::BUILD_METADATA.git_sha.into(),
        #[cfg_attr(target_family = "wasm", expect(clippy::useless_conversion))]
        git_dirty: core_crypto::BUILD_METADATA.git_dirty.into(),
    }
}

#[cfg(target_family = "wasm")]
impl crate::CoreCrypto {
    /// Returns the current version of CoreCrypto
    pub fn version() -> String {
        version()
    }

    /// Returns build data for CoreCrypto
    pub fn build_metadata() -> BuildMetadata {
        build_metadata()
    }
}
