#[cfg(target_family = "wasm")]
use std::sync::Mutex;
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
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(target_family = "wasm")]
use crate::CoreCrypto;

/// Defines the log level for a CoreCrypto
#[derive(Debug, Clone, Copy)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Enum))]
#[repr(u8)]
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

/// This trait is used to provide a callback mechanism to hook up the respective platform logging system.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export(with_foreign)]
pub trait CoreCryptoLogger: std::fmt::Debug + Send + Sync {
    /// Function to setup a hook for the logging messages. Core Crypto will call this method
    /// whenever it needs to log a message.
    fn log(&self, level: CoreCryptoLogLevel, message: String, context: Option<String>);
}

/// This duck-typed interface is used to provide a callback mechanism to hook up the respective platform logging system.
#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    pub type CoreCryptoLogger;

    #[wasm_bindgen(structural, method)]
    pub fn log(this: &CoreCryptoLogger, level: CoreCryptoLogLevel, message: String, context: Option<String>);
}

/// The dummy logger is a suitable default value for the log shim
#[derive(Debug)]
struct DummyLogger;

#[cfg(not(target_family = "wasm"))]
impl CoreCryptoLogger for DummyLogger {
    #[allow(unused_variables)]
    fn log(&self, level: CoreCryptoLogLevel, message: String, context: Option<String>) {}
}

#[cfg(target_family = "wasm")]
impl DummyLogger {
    /// We need a `JsValue` which implements the `CoreCryptoLogger` interface but does nothing. This constructs that.
    fn construct() -> JsValue {
        js_sys::Function::default().into()
    }
}

/// The uniffi log shim is a simple wrapper around the foreign implementer of the trait
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, derive_more::Constructor)]
struct LogShim {
    logger: Arc<dyn CoreCryptoLogger>,
}

#[cfg(not(target_family = "wasm"))]
impl Default for LogShim {
    fn default() -> Self {
        Self {
            logger: Arc::new(DummyLogger),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
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

/// The wasm log shim is a simple wrapper around a duck type implementing the log interface
#[cfg(target_family = "wasm")]
#[derive(Clone)]
struct LogShim {
    logger: Arc<Mutex<CoreCryptoLogger>>,
}

#[cfg(target_family = "wasm")]
// SAFETY: Arc<Mutex<T>> is Send
unsafe impl Send for LogShim {}

#[cfg(target_family = "wasm")]
// SAFETY: Arc<Mutex<T>> is Sync
unsafe impl Sync for LogShim {}

#[cfg(target_family = "wasm")]
impl Default for LogShim {
    fn default() -> Self {
        Self::new(CoreCryptoLogger {
            obj: DummyLogger::construct(),
        })
    }
}

#[cfg(target_family = "wasm")]
impl LogShim {
    fn new(logger: CoreCryptoLogger) -> Self {
        // We manually implement Send and Sync for this struct precisely because of this
        #[expect(clippy::arc_with_non_send_sync)]
        let logger = Arc::new(Mutex::new(logger));
        Self { logger }
    }
}

impl log::Log for LogShim {
    #[cfg_attr(target_family = "wasm", expect(unused_variables))]
    fn enabled(&self, metadata: &Metadata) -> bool {
        cfg_if::cfg_if! {
        if #[cfg(target_family = "wasm")] {
            true
        } else {
            log::max_level() >= self.adjusted_log_level(metadata)
        }}
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

        // uniffi-style
        #[cfg(not(target_family = "wasm"))]
        self.logger.log(
            CoreCryptoLogLevel::from(self.adjusted_log_level(record.metadata())),
            message,
            context,
        );

        // wasm-style
        #[cfg(target_family = "wasm")]
        {
            let guard = self
                .logger
                .lock()
                .expect("we don't panic with the lock so we won't need to panic with the lock");
            guard.log(record.metadata().level().into(), message, context);
        }
    }

    fn flush(&self) {}
}

static INIT_LOGGER: Once = Once::new();
static LOGGER: LazyLock<ReloadLog<LogShim>> = LazyLock::new(|| ReloadLog::new(LogShim::default()));

/// In uniffi the logger interface is a boxed trait instance
#[cfg(not(target_family = "wasm"))]
type Logger = Arc<dyn CoreCryptoLogger>;

/// In wasm the logger interface is a duck-typed `JsValue`
#[cfg(target_family = "wasm")]
type Logger = CoreCryptoLogger;

/// Initializes the logger
///
/// NOTE: in a future  release we will remove `level` argument.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn CoreCryptoLogger>, level: CoreCryptoLogLevel) {
    set_logger_only_inner(logger);
    set_max_log_level(level);
}

fn set_logger_only_inner(logger: Logger) {
    LOGGER
        .handle()
        .replace(LogShim::new(logger))
        .expect("no poisoned locks should be possible as we never panic while holding the lock");

    INIT_LOGGER.call_once(|| {
        log::set_logger(LOGGER.deref())
            .expect("no poisonsed locks should be possible as we never panic while holding the lock");
        log::set_max_level(LevelFilter::Warn);
    });
}

/// Initializes the logger
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub fn set_logger_only(logger: Logger) {
    set_logger_only_inner(logger);
}

/// Set maximum log level forwarded to the logger
#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
pub fn set_max_log_level(level: CoreCryptoLogLevel) {
    log::set_max_level(level.into());
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    pub fn set_logger(logger: CoreCryptoLogger) {
        set_logger_only_inner(logger);
    }

    pub fn set_max_log_level(level: CoreCryptoLogLevel) {
        log::set_max_level(level.into());
    }
}
