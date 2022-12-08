#![allow(dead_code)]

pub type Extensible = Option<std::collections::HashMap<String, serde_json::Value>>;

pub mod browsing_context;
pub mod log;
pub mod protocol;
pub mod script;
pub mod session;

pub mod remote {
    use crate::webdriver_bidi::Extensible;

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct Command {
        id: u64,
        data: CommandData,
        rest: Extensible,
    }

    // TODO: Add actual commands
    #[derive(Debug, Clone)]
    pub enum CommandData {
        BrowsingContextCommand, //(BrowsingContextCommand),
        ScriptCommand,          //(ScriptCommand),
        SessionCommand,         //(SessionCommand),
    }

    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct EmptyParams(Extensible);
}

pub mod local {
    use crate::webdriver_bidi::Extensible;

    #[derive(Debug, Clone)]
    pub enum Message {
        CommandResponse(CommandResponse),
        ErrorResponse(ErrorResponse),
        Event(Event),
    }

    #[derive(Debug, Clone)]
    pub struct CommandResponse {
        id: u64,
        result: ResultData,
        rest: Extensible,
    }

    #[derive(Debug, Clone, thiserror::Error)]
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

    #[derive(Debug, Clone)]
    pub struct ErrorResponse {
        id: Option<u64>,
        error: ErrorCode,
        message: String,
        stacktrace: Option<String>,
        rest: Extensible,
    }

    #[derive(Debug, Clone)]
    #[repr(transparent)]
    pub struct EmptyResult(Extensible);

    // TODO: Add actual events
    #[derive(Debug, Clone)]
    pub enum EventData {
        BrowsingContextEvent,
        ScriptEvent,
        LogEvent,
    }

    #[derive(Debug, Clone)]
    pub enum Event {
        EventData(EventData),
        Extensible(Extensible),
    }

    #[derive(Debug, Clone)]
    pub enum ResultData {
        EmptyResult(EmptyResult),
        SessionResult,
        BrowsingContextResult,
        ScriptResult,
    }

    pub type Handle = String;

    #[derive(Debug, Clone)]
    pub struct RemoteReference {
        handle: Handle,
        rest: Extensible,
    }
}
