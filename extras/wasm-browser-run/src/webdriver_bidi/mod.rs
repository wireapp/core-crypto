#![allow(dead_code)]

pub type Extensible = Option<std::collections::HashMap<String, serde_json::Value>>;

pub mod browsing_context;
pub mod log;
pub mod protocol;
pub mod script;
pub mod session;

pub mod remote {
    use crate::webdriver_bidi::Extensible;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[non_exhaustive]
    pub struct Command {
        pub id: u64,
        pub data: CommandData,
        pub rest: Extensible,
    }

    // TODO: Add actual commands
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum CommandData {
        BrowsingContextCommand, //(BrowsingContextCommand),
        ScriptCommand,          //(ScriptCommand),
        SessionCommand,         //(SessionCommand),
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[repr(transparent)]
    pub struct EmptyParams(pub Extensible);
}

pub mod local {
    use crate::webdriver_bidi::browsing_context::BrowsingContextEvent;
    use crate::webdriver_bidi::log::LogEvent;
    use crate::webdriver_bidi::script::ScriptEvent;
    use crate::webdriver_bidi::Extensible;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Message {
        CommandResponse(CommandResponse),
        ErrorResponse(ErrorResponse),
        Event(Event),
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct CommandResponse {
        pub id: u64,
        pub result: ResultData,
        pub rest: Extensible,
    }

    #[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
    pub enum ErrorCode {
        #[error("invalid argument")]
        InvalidArgument,
        #[error("no such alert")]
        NoSuchAlert,
        #[error("no such frame")]
        NoSuchFrame,
        #[error("session not created")]
        SessionNotCreated,
        #[error("unknown command")]
        UnknownCommand,
        #[error("unknown error")]
        UnknownError,
        #[error("unsupported operation")]
        UnsupportedOperation,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct ErrorResponse {
        pub id: Option<u64>,
        pub error: ErrorCode,
        pub message: String,
        pub stacktrace: Option<String>,
        pub rest: Extensible,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[repr(transparent)]
    pub struct EmptyResult(Extensible);

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum EventData {
        LogEvent(LogEvent),
        BrowsingContextEvent(BrowsingContextEvent),
        ScriptEvent(ScriptEvent),
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Event {
        #[serde(flatten)]
        pub data: EventData,
        #[serde(flatten)]
        pub rest: Extensible,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub enum ResultData {
        EmptyResult(EmptyResult),
        SessionResult,
        BrowsingContextResult,
        ScriptResult,
    }

    pub type Handle = String;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct RemoteReference {
        pub handle: Handle,
        pub rest: Extensible,
    }
}
