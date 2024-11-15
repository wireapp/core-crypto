/// Metadata describing the conditions of the build of this software.
pub struct BuildMetadata {
    /// Build Timestamp
    pub timestamp: &'static str,
    /// Whether this build was in Debug mode (true) or Release mode (false)
    pub cargo_debug: &'static str,
    /// Features enabled for this build
    pub cargo_features: &'static str,
    /// Optimization level
    pub opt_level: &'static str,
    /// Build target triple
    pub target_triple: &'static str,
    /// Git branch
    pub git_branch: &'static str,
    /// Output of `git describe`
    pub git_describe: &'static str,
    /// Hash of current git commit
    pub git_sha: &'static str,
    /// `true` when the source code differed from the commit at the most recent git hash
    pub git_dirty: &'static str,
}

/// Metadata describing the conditions of the build of this software.
pub const BUILD_METADATA: BuildMetadata = BuildMetadata {
    timestamp: env!("VERGEN_BUILD_TIMESTAMP"),
    cargo_debug: env!("VERGEN_CARGO_DEBUG"),
    cargo_features: env!("VERGEN_CARGO_FEATURES"),
    opt_level: env!("VERGEN_CARGO_OPT_LEVEL"),
    target_triple: env!("VERGEN_CARGO_TARGET_TRIPLE"),
    git_branch: env!("VERGEN_GIT_BRANCH"),
    git_describe: env!("VERGEN_GIT_DESCRIBE"),
    git_sha: env!("VERGEN_GIT_SHA"),
    git_dirty: env!("VERGEN_GIT_DIRTY"),
};
