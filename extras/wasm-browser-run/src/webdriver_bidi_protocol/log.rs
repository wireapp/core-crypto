use super::protocol::RemoteValue;
use super::script::{ScriptSource, ScriptStackTrace};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Debug => "DEBUG",
                Self::Info => "INFO",
                Self::Warn => "WARN",
                Self::Error => "ERROR",
            }
        )
    }
}

impl Into<tracing::level_filters::LevelFilter> for LogLevel {
    fn into(self) -> tracing::level_filters::LevelFilter {
        match self {
            Self::Error => tracing::level_filters::LevelFilter::ERROR,
            Self::Warn => tracing::level_filters::LevelFilter::WARN,
            Self::Info => tracing::level_filters::LevelFilter::INFO,
            Self::Debug => tracing::level_filters::LevelFilter::DEBUG,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseLogEntry {
    pub level: LogLevel,
    #[serde(flatten)]
    pub source: ScriptSource,
    pub text: Option<String>,
    // FIXME: Do something better than a f64; ie std::time::Duration or something like chrono human durations
    pub timestamp: f64,
    pub stack_trace: Option<ScriptStackTrace>,
}

impl std::fmt::Display for BaseLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[{}] at {}:", self.timestamp, self.source)?;
        if let Some(text) = &self.text {
            writeln!(f, "{text}")?;
        }
        if let Some(strace) = &self.stack_trace {
            for (i, sframe) in strace.call_frames.iter().enumerate() {
                write!(f, "\t#{i} {sframe}")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConsoleLogEntry {
    pub method: String,
    pub args: Vec<RemoteValue>,
    #[serde(flatten)]
    pub entry: BaseLogEntry,
}

impl std::fmt::Display for ConsoleLogEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let args = self
            .args
            .iter()
            .map(|e| format!("{:?}", e))
            .collect::<Vec<String>>()
            .join(", ");

        writeln!(f, "\tcallsite:: {}({})", self.method, args)?;
        writeln!(f, "{}", self.entry)?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde_enum_str::Serialize_enum_str, serde_enum_str::Deserialize_enum_str)]
#[serde(rename_all = "lowercase")]
pub enum LogEntryType {
    Console,
    JavaScript,
    #[serde(other)]
    Generic(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum LogEntryInner {
    Console(ConsoleLogEntry),
    Base(BaseLogEntry),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    #[serde(rename = "type")]
    pub entry_type: LogEntryType,
    #[serde(flatten)]
    pub entry_data: LogEntryInner,
}

impl LogEntry {
    pub fn get_text(&self) -> Option<&str> {
        match &self.entry_data {
            LogEntryInner::Console(console_log) => console_log.entry.text.as_ref().map(|s| s.as_ref()),
            LogEntryInner::Base(generic_log) => generic_log.text.as_ref().map(|s| s.as_ref()),
        }
    }

    pub fn get_level(&self) -> LogLevel {
        let entry = match &self.entry_data {
            LogEntryInner::Console(console_log) => &console_log.entry,
            LogEntryInner::Base(entry) => entry,
        };

        entry.level
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum LogEvent {
    #[serde(rename = "log.entryAdded")]
    EntryAdded(LogEntry),
}
