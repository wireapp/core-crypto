use crate::webdriver_bidi::browsing_context::BrowsingContext;

pub type ScriptRealm = String;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ScriptRealmType {
    Window,
    DedicatedWorker,
    SharedWorker,
    ServiceWorker,
    Worker,
    PaintWorklet,
    AudioWorklet,
    Worklet,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ScriptResultOwnership {
    Root,
    None,
}

#[derive(Debug, Clone)]
pub struct ScriptSource {
    realm: ScriptRealm,
    context: Option<BrowsingContext>,
}

#[derive(Debug, Clone)]
pub struct ScriptRealmTarget {
    realm: ScriptRealm,
}

#[derive(Debug, Clone)]
pub struct ScriptContextTarget {
    context: BrowsingContext,
    sandbox: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScriptTarget {
    Realm(ScriptRealmTarget),
    Context(ScriptContextTarget),
}

#[derive(Debug, Clone)]
pub struct ScriptStackFrame {
    column_number: u64,
    line_number: u64,
    function_name: String,
    url: String,
}

pub type ScriptStackTrace = Vec<ScriptStackFrame>;

#[derive(Debug, Clone)]
pub struct ScriptExceptionDetails {
    column_number: u64,
    exception: RemoteValue,
    line_number: u64,
    stack_trace: ScriptStackTrace,
    text: String,
}
