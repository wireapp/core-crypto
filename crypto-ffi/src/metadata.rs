const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The version of `core-crypto`.
#[uniffi::export]
pub fn version() -> String {
    VERSION.to_string()
}

// Unfortunately, we need to define the `BuildMetadata` struct twice:
// not only does it require a different fundamental member type, but
// the `wasm_bindgen` attribute on the struct members is not compatible
// with the `#[cfg_attr]` attribute.

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

/// Returns build data for CoreCrypto
#[uniffi::export]
pub fn build_metadata() -> BuildMetadata {
    BuildMetadata {
        timestamp: core_crypto::BUILD_METADATA.timestamp.into(),
        cargo_debug: core_crypto::BUILD_METADATA.cargo_debug.into(),
        cargo_features: core_crypto::BUILD_METADATA.cargo_features.into(),
        opt_level: core_crypto::BUILD_METADATA.opt_level.into(),
        target_triple: core_crypto::BUILD_METADATA.target_triple.into(),
        git_branch: core_crypto::BUILD_METADATA.git_branch.into(),
        git_describe: core_crypto::BUILD_METADATA.git_describe.into(),
        git_sha: core_crypto::BUILD_METADATA.git_sha.into(),
        git_dirty: core_crypto::BUILD_METADATA.git_dirty.into(),
    }
}
