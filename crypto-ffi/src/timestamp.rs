//! Custom timestamp type for UniFFI bindings.
//!
//! This wrapper allows custom type mapping per target language:
//! - Kotlin: maps to `kotlinx.datetime.Instant`
//! - Swift: maps to `Date`
//! - WASM/JS: maps to `Date` (via uniffi-bindgen-react-native)
//!
//! This unifies timestamp handling across JVM/Android, KMP.
//! This can be removed once we fully migrate to Kotlin Multiplatform and
//! stop generating JVM/Android bindings.

use std::time::{Duration, SystemTime};

/// A wrapper around `SystemTime` for FFI bindings with custom type mapping per language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub SystemTime);

impl Timestamp {
    /// Creates a new `Timestamp` from a `SystemTime`.
    pub fn new(time: SystemTime) -> Self {
        Self(time)
    }

    /// Creates a new `Timestamp` from seconds since the Unix epoch.
    pub fn from_epoch_secs(secs: u64) -> Self {
        Self(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Returns the inner `SystemTime`.
    pub fn into_inner(self) -> SystemTime {
        self.0
    }
}

impl From<SystemTime> for Timestamp {
    fn from(time: SystemTime) -> Self {
        Self(time)
    }
}

impl From<Timestamp> for SystemTime {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

uniffi::custom_type!(Timestamp, SystemTime);
