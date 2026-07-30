#[cfg(not(target_os = "unknown"))]
pub(crate) mod transaction_helper;

use std::sync::Arc;

#[cfg(feature = "cancellable-transactions")]
use futures_util::FutureExt;

#[cfg(feature = "cancellable-transactions")]
use crate::{CoreCryptoCancellationToken, CoreCryptoError};
use crate::{CoreCryptoContext, CoreCryptoFfi, CoreCryptoResult};

/// A `CoreCryptoCommand` has an `execute` method which accepts a `CoreCryptoContext` and returns nothing.
///
/// It is the argument to a `CoreCrypto::transaction` call.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub trait CoreCryptoCommand: Send + Sync {
    /// Will be called inside a transaction in CoreCrypto
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()>;
}

/// When building outside WASM, any async function of appropriate signature is a `CoreCryptoCommand`.

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl<F, Fut> CoreCryptoCommand for F
where
    F: Fn(Arc<CoreCryptoContext>) -> Fut + Send + Sync,
    Fut: Future<Output = CoreCryptoResult<()>> + Send,
{
    async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
        self(context).await
    }
}

/// In uniffi, a Command is an Arc wrapping a dyn trait object
type Command = Arc<dyn CoreCryptoCommand>;

#[uniffi::export]
impl CoreCryptoFfi {
    /// Starts a new transaction in Core Crypto. If the callback succeeds, it will be committed,
    /// otherwise, every operation performed with the context will be discarded.
    ///
    /// When calling this function from within Rust, async functions accepting a context
    /// implement `CoreCryptoCommand`, so operations can be defined inline as follows:
    ///
    /// ```ignore
    /// core_crypto.transaction(Arc::new(async |context| {
    ///     // your implementation here
    ///     Ok(())
    /// }))?;
    /// ```
    pub async fn transaction_ffi(&self, command: Command) -> CoreCryptoResult<()> {
        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 1; "awaiting transaction semaphore");
        let inner_context = Arc::new(self.inner.new_transaction().await?);
        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 2; "acquired semaphore; creating context");

        let context = CoreCryptoContext {
            inner: inner_context.clone(),
            #[cfg(feature = "cancellable-transactions")]
            cancellation_slot: self.cancellation_slot.clone(),
        };

        // We need one more layer of Arc-wrapping in uniffi. It's kind of silly, given the
        // also-mandatory Arc-wrapping internally, but that's the price we have to pay in order
        // to reuse the code in both target contexts.
        let context = Arc::new(context);

        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 3; "created context; executing command");
        let result = command.execute(context).await;
        match result {
            Ok(()) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = true; "command succeeded; committing transaction");
                inner_context.finish().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = true; "exiting successfully");
                Ok(())
            }
            Err(err) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = false; "command failed; aborting transaction");
                inner_context.abort().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = false, err:err; "exiting propagating error");
                Err(err)
            }
        }
    }
}

#[cfg(feature = "cancellable-transactions")]
#[uniffi::export]
impl CoreCryptoFfi {
    /// Like `transaction_ffi`, but cancellable.
    ///
    /// Cancelling the token aborts the transaction and stops waiting for any
    /// in-flight `MlsTransport` callback or `PkiEnvironment` hook associated with it.
    ///
    /// For implementation details, see the [`cancellation` docs][crate::cancellation].
    pub async fn transaction_ffi_cancellable(
        &self,
        command: Command,
        cancellation: Arc<CoreCryptoCancellationToken>,
    ) -> CoreCryptoResult<()> {
        log::info!(
            scope = "CoreCryptoFfi::transaction_ffi", stage = 1;
            "racing cancellation token against acquisition of transaction semaphore"
        );
        // Prefer cancellation so a pre-cancelled token cannot start a transaction.
        let inner_context = futures_util::select_biased! {
            _ = cancellation.cancelled().fuse() => return Err(CoreCryptoError::TransactionCanceled),
            inner_context_result = self.inner.new_transaction().fuse() => inner_context_result?,
        };

        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 2; "acquired semaphore; creating context");
        let inner_context = Arc::new(inner_context);

        // Only the transaction owning the semaphore may publish its token. These guards
        // are declared after the context so the slots are cleared before the semaphore is released.
        let _cancellation_guard = self.cancellation_slot.enter(cancellation.clone())?;
        let pki_cancellation_slot = self
            .pki_environment
            .read()
            .await
            .as_ref()
            .map(|environment| environment.cancellation_slot.clone());
        let _pki_cancellation_guard = pki_cancellation_slot
            .map(|slot| slot.enter(cancellation.clone()))
            .transpose()?;

        let context = CoreCryptoContext {
            inner: inner_context.clone(),
            cancellation_slot: self.cancellation_slot.clone(),
        };

        let context = Arc::new(context);

        log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 3; "created context; racing command against cancellation");

        // Prefer cancellation when both futures become ready together.
        let result = futures_util::select_biased! {
            _ = cancellation.cancelled().fuse() => Err(CoreCryptoError::TransactionCanceled),
            result = command.execute(context).fuse() => result,
        };

        match result {
            Ok(()) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = true; "command succeeded; committing transaction");
                inner_context.finish().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = true; "exiting successfully");
                Ok(())
            }
            Err(err) => {
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 4, command_success = false; "command failed; aborting transaction");
                inner_context.abort().await?;
                log::info!(scope = "CoreCryptoFfi::transaction_ffi", stage = 5, command_success = false, err:err; "exiting propagating error");
                Err(err)
            }
        }
    }
}

#[cfg(all(test, feature = "cancellable-transactions", not(target_os = "unknown")))]
mod tests {
    use std::sync::Arc;

    use async_lock::Semaphore;
    use core_crypto::{CipherSuite as CryptoCipherSuite, Credential as CryptoCredential};

    use crate::{
        ClientId, CommitBundle, ConversationId, CoreCryptoCancellationToken, CoreCryptoCommand, CoreCryptoContext,
        CoreCryptoResult, Credential, Database, DeviceId, EpochObserver, HistorySecret, MlsTransport, MlsTransportData,
        MlsTransportResult, Uuid, cipher_suite_default, core_crypto::epoch_observer::EpochChangedReportingError,
        core_crypto_new,
    };

    const CLIENT_UUID: &str = "00000000-0000-4000-8000-000000000000";
    const DOMAIN: &str = "example.com";

    /// Accepts every commit bundle without doing anything.
    #[derive(Debug)]
    struct AcceptingTransport;

    #[async_trait::async_trait]
    impl MlsTransport for AcceptingTransport {
        async fn send_commit_bundle(&self, _commit_bundle: CommitBundle) -> MlsTransportResult {
            Ok(())
        }

        async fn prepare_for_transport(&self, _history_secret: HistorySecret) -> MlsTransportData {
            unreachable!("this test never shares history")
        }
    }

    /// Parks inside the epoch-change notification until `release` is signalled.
    ///
    /// `TransactionContext::finish` notifies epoch observers *after* the keystore transaction has
    /// committed and released the transaction semaphore, so parking here holds the first
    /// transaction in precisely the window where the second transaction starts.
    struct ParkingEpochObserver {
        release: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl EpochObserver for ParkingEpochObserver {
        async fn epoch_changed(
            &self,
            _conversation_id: Arc<ConversationId>,
            _epoch: u64,
        ) -> Result<(), EpochChangedReportingError> {
            let _permit = self.release.acquire().await;
            Ok(())
        }
    }

    /// Initializes MLS, adds a basic credential, and creates the conversation the test commits to.
    struct Setup {
        client_id: Arc<ClientId>,
        conversation_id: ConversationId,
    }

    #[async_trait::async_trait]
    impl CoreCryptoCommand for Setup {
        async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
            context.mls_init(&self.client_id, Arc::new(AcceptingTransport)).await?;

            let credential = CryptoCredential::basic(
                CryptoCipherSuite::from(cipher_suite_default()),
                self.client_id.as_ref().as_ref().to_owned(),
            )?;
            let credential_ref = context.add_credential(Arc::new(Credential::from(credential))).await?;

            context
                .create_conversation(&self.conversation_id, &credential_ref, None)
                .await
        }
    }

    /// Updates the conversation's key material, which queues an epoch-change notification.
    struct ChangeEpoch {
        conversation_id: ConversationId,
    }

    #[async_trait::async_trait]
    impl CoreCryptoCommand for ChangeEpoch {
        async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
            context.update_keying_material(&self.conversation_id).await
        }
    }

    /// Releases the parked epoch observer so the first transaction can finish.
    ///
    /// Running at all is the property under test: this command only executes once
    /// `transaction_ffi_cancellable` has put its own token into the cancellation slot, which it
    /// cannot do while the previous transaction's token is still there.
    struct ReleaseObserver {
        release: Arc<Semaphore>,
    }

    #[async_trait::async_trait]
    impl CoreCryptoCommand for ReleaseObserver {
        async fn execute(&self, context: Arc<CoreCryptoContext>) -> CoreCryptoResult<()> {
            self.release.add_permits(1);
            context.set_data(b"the second transaction ran".to_vec()).await
        }
    }

    /// A transaction must be able to start while the previous transaction's epoch observer runs.
    ///
    /// The keystore releases the transaction semaphore as its commit completes, which is before
    /// `finish` notifies epoch observers. So if `transaction_ffi_cancellable` held its cancellation
    /// guards until it returned, the waiting transaction would acquire the semaphore while the
    /// previous transaction's token was still in the slot, and `CancellationSlot::enter` would
    /// panic.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn transaction_can_start_while_previous_epoch_observer_runs() {
        let database = Arc::new(Database::in_memory().await.unwrap());
        let core_crypto = core_crypto_new(&database).unwrap();

        let client_id = Arc::new(ClientId::new(
            Arc::new(Uuid::new(CLIENT_UUID).unwrap()),
            Arc::new(DeviceId::new(1)),
            DOMAIN.to_owned(),
        ));
        let conversation_id = ConversationId::new(b"epoch observer conversation".to_vec());

        core_crypto
            .transaction_ffi(Arc::new(Setup {
                client_id,
                conversation_id: conversation_id.clone(),
            }))
            .await
            .unwrap();

        let release = Arc::new(Semaphore::new(0));
        core_crypto
            .register_epoch_observer(Arc::new(ParkingEpochObserver {
                release: release.clone(),
            }))
            .await
            .unwrap();

        // A single-threaded executor polls these in order, so the interleaving is deterministic:
        // the first transaction acquires the semaphore immediately and runs until it parks in the
        // epoch observer, by which point it has committed and released the semaphore. Only then
        // does the second transaction get to acquire it and reach for the cancellation slot.
        let (epoch_change, next_transaction) = futures_util::future::join(
            core_crypto.transaction_ffi_cancellable(
                Arc::new(ChangeEpoch { conversation_id }),
                Arc::new(CoreCryptoCancellationToken::new()),
            ),
            core_crypto.transaction_ffi_cancellable(
                Arc::new(ReleaseObserver { release }),
                Arc::new(CoreCryptoCancellationToken::new()),
            ),
        )
        .await;

        epoch_change.unwrap();
        next_transaction.unwrap();
    }
}
