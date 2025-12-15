use crate::entities::{PersistedMlsGroup, PersistedMlsGroupExt};

#[async_trait::async_trait(?Send)]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }
}
