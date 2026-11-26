/// Whether a conversation is pending or initialized
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    /// The conversation is operational
    #[default]
    Operational,
    /// The conversation is pending, waiting for a commit to make it operational
    Pending,
}

impl PendingStatus {
    /// `true` when this status is pending
    #[inline]
    pub fn is_pending(self) -> bool {
        match self {
            PendingStatus::Operational => false,
            PendingStatus::Pending => true,
        }
    }

    /// Create an instance from an `is_pending` boolean
    #[inline]
    pub fn from_is_pending(is_pending: bool) -> Self {
        if is_pending { Self::Pending } else { Self::Operational }
    }
}
