use crate::transaction_context::TransactionContext;

impl TransactionContext {
    /// See [crate::mls::session::Session::e2ei_is_pki_env_setup].
    pub async fn e2ei_is_pki_env_setup(&self) -> bool {
        self.pki_environment().await.ok().flatten().is_some()
    }
}
