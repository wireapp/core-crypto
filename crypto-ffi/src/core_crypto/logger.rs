use std::{
    collections::BTreeMap,
    ops::Deref as _,
    sync::{Arc, LazyLock, Once},
};

use log::{
    Level, LevelFilter, Metadata, Record,
    kv::{Key, Value, VisitSource},
};
use log_reload::ReloadLog;

/// Defines the log level for a CoreCrypto
#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
#[expect(missing_docs)] // these are standard log levels and additional docs are pointless
pub enum CoreCryptoLogLevel {
    Off = 1,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<CoreCryptoLogLevel> for LevelFilter {
    fn from(value: CoreCryptoLogLevel) -> LevelFilter {
        match value {
            CoreCryptoLogLevel::Off => LevelFilter::Off,
            CoreCryptoLogLevel::Trace => LevelFilter::Trace,
            CoreCryptoLogLevel::Debug => LevelFilter::Debug,
            CoreCryptoLogLevel::Info => LevelFilter::Info,
            CoreCryptoLogLevel::Warn => LevelFilter::Warn,
            CoreCryptoLogLevel::Error => LevelFilter::Error,
        }
    }
}

impl From<Level> for CoreCryptoLogLevel {
    fn from(value: Level) -> Self {
        match value {
            Level::Warn => CoreCryptoLogLevel::Warn,
            Level::Error => CoreCryptoLogLevel::Error,
            Level::Info => CoreCryptoLogLevel::Info,
            Level::Debug => CoreCryptoLogLevel::Debug,
            Level::Trace => CoreCryptoLogLevel::Trace,
        }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum LoggingError {
    #[error("panic or otherwise unexpected error from foreign code")]
    Ffi(#[from] uniffi::UnexpectedUniFFICallbackError),
}

/// This trait is used to provide a callback mechanism to hook up the respective platform logging system.
#[uniffi::export(with_foreign)]
pub trait CoreCryptoLogger: std::fmt::Debug + Send + Sync {
    /// Core Crypto will call this method whenever it needs to log a message.
    ///
    /// This function catches panics and other unexpected errors. In those cases, it writes to `stderr`.
    fn log(&self, level: CoreCryptoLogLevel, message: String, context: Option<String>) -> Result<(), LoggingError>;
}

/// The dummy logger is a suitable default value for the log shim
#[derive(Debug)]
struct DummyLogger;

impl CoreCryptoLogger for DummyLogger {
    #[allow(unused_variables)]
    fn log(&self, level: CoreCryptoLogLevel, message: String, context: Option<String>) -> Result<(), LoggingError> {
        Ok(())
    }
}

/// The uniffi log shim is a simple wrapper around the foreign implementer of the trait
#[derive(Clone, derive_more::Constructor)]
struct LogShim {
    logger: Arc<dyn CoreCryptoLogger>,
}

impl Default for LogShim {
    fn default() -> Self {
        Self {
            logger: Arc::new(DummyLogger),
        }
    }
}

impl LogShim {
    fn adjusted_log_level(&self, metadata: &Metadata) -> Level {
        match (metadata.level(), metadata.target()) {
            // increase log level for refinery_core::traits since they are too verbose in transactions
            (level, "refinery_core::traits") if level >= Level::Info => Level::Debug,
            (level, "refinery_core::traits::sync") if level >= Level::Info => Level::Debug,
            (level, _) => level,
        }
    }
}

impl log::Log for LogShim {
    fn enabled(&self, metadata: &Metadata) -> bool {
        log::max_level() >= self.adjusted_log_level(metadata)
    }

    fn log(&self, record: &Record) {
        struct KeyValueVisitor<'kvs>(BTreeMap<Key<'kvs>, Value<'kvs>>);

        impl<'kvs> VisitSource<'kvs> for KeyValueVisitor<'kvs> {
            #[inline]
            fn visit_pair(&mut self, key: Key<'kvs>, value: Value<'kvs>) -> Result<(), log::kv::Error> {
                self.0.insert(key, value);
                Ok(())
            }
        }

        let kvs = record.key_values();
        let mut visitor = KeyValueVisitor(BTreeMap::new());
        let _ = kvs.visit(&mut visitor);

        if !self.enabled(record.metadata()) {
            return;
        }

        let message = format!("{}", record.args());
        let context = serde_json::to_string(&visitor.0).ok();

        // adjust the loglevel for sqlite migrations
        #[cfg(not(target_family = "wasm"))]
        let loglevel = CoreCryptoLogLevel::from(self.adjusted_log_level(record.metadata()))

        // no adjustment needed for wasm/idb
        #[cfg(target_family = "wasm")]
        let loglevel = record.metadata().level()

        let log_result = self.logger.log(
            loglevel,
            message.clone(),
            context,
        );
        if let Err(LoggingError::Ffi(meta_err @ uniffi::UnexpectedUniFFICallbackError { .. })) = log_result {
            eprintln!("{meta_err} while attempting to produce {message}");
        }
    }

    fn flush(&self) {}
}

static INIT_LOGGER: Once = Once::new();
static LOGGER: LazyLock<ReloadLog<LogShim>> = LazyLock::new(|| ReloadLog::new(LogShim::default()));

/// Initializes the logger
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn CoreCryptoLogger>) {
    LOGGER
        .handle()
        .replace(LogShim::new(logger))
        .expect("no poisoned locks should be possible as we never panic while holding the lock");

    INIT_LOGGER.call_once(|| {
        log::set_logger(LOGGER.deref())
            .expect("no poisoned locks should be possible as we never panic while holding the lock");
        log::set_max_level(LevelFilter::Warn);
    });
}

/// Set maximum log level forwarded to the logger
#[uniffi::export]
pub fn set_max_log_level(level: CoreCryptoLogLevel) {
    log::set_max_level(level.into());
}
