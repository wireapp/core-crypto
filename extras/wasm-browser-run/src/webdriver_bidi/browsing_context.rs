pub type BrowsingContext = String;
pub type BrowsingContextInfoList = Vec<BrowsingContextInfo>;
pub type BrowsingContextNavigation = String;

#[derive(Debug, Clone)]
pub struct BrowsingContextInfo {
    context: BrowsingContext,
    url: String,
    children: Option<BrowsingContextInfoList>,
    parent: Option<BrowsingContext>,
}

#[derive(Debug, Clone)]
pub struct BrowsingContextNavigationInfo {
    context: BrowsingContext,
    navigation: Option<BrowsingContextNavigation>,
    url: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BrowsingContextReadinessState {
    None,
    Interactive,
    Complete,
}
