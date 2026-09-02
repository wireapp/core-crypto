use crate::{CryptoKeystoreError, Transaction};

impl Transaction {
    /// Do an operation within the context of a savepoint.
    ///
    /// <https://sqlite.org/lang_savepoint.html>
    ///
    /// A savepoint is like a transaction, but has a name and can be nested.
    /// This allows for more fine-grained control over what makes it into the history,
    /// or not.
    ///
    /// The operation produces an arbitrary result which is forwarded unmodified to the
    /// output of this method. If that result is ok, the savepoint is released (i.e. committed).
    /// If that result is an error, the savepoint is rolled back.
    ///
    /// Error-mapping is the most complicated part of this. When an error is produced in the course
    /// of this method, we run the `map_err` function with a static context string describing what was
    /// happening. That function must return a second function which transforms a [`CryptoKeystoreError`]
    /// into an instance of `E`.
    pub async fn with_savepoint<T, E>(
        &self,
        savepoint_name: &str,
        operation: impl AsyncFnOnce() -> Result<T, E>,
        map_err: impl Fn(&'static str) -> Box<dyn FnOnce(CryptoKeystoreError) -> E>,
    ) -> Result<T, E> {
        // note that in this function we don't bother caching the sql statements; they're kind of
        // ad-hoc given the variable savepoint name, so we'd expect mostly cache misses anyway

        // We'll need to release this guard and its locks so the interior operation can acquire them
        {
            let conn = self
                .conn()
                .map_err(map_err("getting sql connection to create savepoint"))?;
            let mut stmt = conn
                .prepare(&format!("SAVEPOINT {savepoint_name}"))
                .map_err(Into::into)
                .map_err(map_err("preparing statement to create savepoint"))?;
            stmt.execute([])
                .map_err(Into::into)
                .map_err(map_err("creating savepoint"))?;
        }

        let outcome = operation().await;

        // time to finalize the savepoint one way or the other
        let conn = self
            .conn()
            .map_err(map_err("getting sql connection to finalize savepoint"))?;

        if outcome.is_ok() {
            let mut stmt = conn
                .prepare(&format!("RELEASE SAVEPOINT {savepoint_name}"))
                .map_err(Into::into)
                .map_err(map_err("creating savepoint release stmt"))?;
            stmt.execute([])
                .map_err(Into::into)
                .map_err(map_err("releasing savepoint"))?;
        } else {
            let mut stmt = conn
                .prepare(&format!("ROLLBACK TO SAVEPOINT {savepoint_name}"))
                .map_err(Into::into)
                .map_err(map_err("creating savepoint rollback stmt"))?;
            stmt.execute([])
                .map_err(Into::into)
                .map_err(map_err("rolling back savepoint"))?;
        }

        outcome
    }
}
