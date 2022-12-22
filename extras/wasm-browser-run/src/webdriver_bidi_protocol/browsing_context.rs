pub type BrowsingContext = String;
pub type BrowsingContextInfoList = Vec<BrowsingContextInfo>;
pub type BrowsingContextNavigation = String;

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BrowsingContextInfo {
    pub context: BrowsingContext,
    pub url: String,
    pub children: Option<BrowsingContextInfoList>,
    pub parent: Option<BrowsingContext>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BrowsingContextNavigationInfo {
    pub context: BrowsingContext,
    pub navigation: Option<BrowsingContextNavigation>,
    pub url: String,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowsingContextReadinessState {
    None,
    Interactive,
    Complete,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowsingContextUserPromptType {
    Alert,
    Confirm,
    Prompt,
    BeforeUnload,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum BrowsingContextEvent {
    #[serde(rename = "browsingContext.contextCreated")]
    ContextCreated(BrowsingContextInfo),
    #[serde(rename = "browsingContext.contextDestroyed")]
    ContextDestroyed(BrowsingContextInfo),
    #[serde(rename = "browsingContext.navigationStarted")]
    NavigationStarted(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.fragmentNavigated")]
    FragmentNavigated(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.domConentLoaded")]
    DomContentLoaded(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.load")]
    Load(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.downloadWillBegin")]
    DownloadWillBegin(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.navigationAborted")]
    NavigationAborted(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.navigationFailed")]
    NavigationFailed(BrowsingContextNavigationInfo),
    #[serde(rename = "browsingContext.userPromptClosed")]
    UserPromptClosed {
        context: BrowsingContext,
        accepted: bool,
        user_text: Option<String>,
    },
    #[serde(rename = "browsingContext.userPromptOpened")]
    UserPromptOpened {
        context: BrowsingContext,
        #[serde(rename = "type")]
        prompt_type: BrowsingContextUserPromptType,
        message: String,
    },
}
