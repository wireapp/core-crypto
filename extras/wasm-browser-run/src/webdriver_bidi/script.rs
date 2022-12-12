use crate::webdriver_bidi::browsing_context::BrowsingContext;
use crate::webdriver_bidi::protocol::RemoteValue;

pub type ScriptRealm = String;

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptResultOwnership {
    Root,
    None,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScriptSource {
    pub realm: ScriptRealm,
    pub context: Option<BrowsingContext>,
}

impl std::fmt::Display for ScriptSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.realm)?;
        if let Some(ctx) = &self.context {
            write!(f, " [ctx = {ctx}]")?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptRealmTarget {
    pub realm: ScriptRealm,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptContextTarget {
    pub context: BrowsingContext,
    pub sandbox: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ScriptTarget {
    Realm(ScriptRealmTarget),
    Context(ScriptContextTarget),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScriptStackFrame {
    pub column_number: u64,
    pub line_number: u64,
    pub function_name: String,
    pub url: String,
}

impl std::fmt::Display for ScriptStackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(
            f,
            "{} at {}:{}:{}",
            self.function_name, self.url, self.line_number, self.column_number
        )
    }
}

pub type ScriptStackTrace = Vec<ScriptStackFrame>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptExceptionDetails {
    pub column_number: u64,
    pub exception: RemoteValue,
    pub line_number: u64,
    pub stack_trace: ScriptStackTrace,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScriptBaseRealmInfo {
    pub realm: ScriptRealm,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScriptWindowRealmInfo {
    pub context: BrowsingContext,
    pub sandbox: Option<String>,
    #[serde(flatten)]
    pub entry: ScriptBaseRealmInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScriptRealmInfoInner {
    Window(ScriptWindowRealmInfo),
    Generic(ScriptBaseRealmInfo),
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ScriptRealmInfo {
    #[serde(rename = "type")]
    pub realm_type: ScriptRealmType,
    #[serde(flatten)]
    pub realm_info: ScriptRealmInfoInner,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum ScriptEvent {
    #[serde(rename = "script.realmCreated")]
    RealmCreated(ScriptRealmInfo),
    #[serde(rename = "script.realmDestroyed")]
    RealmDestroyed { realm: ScriptRealm },
}
