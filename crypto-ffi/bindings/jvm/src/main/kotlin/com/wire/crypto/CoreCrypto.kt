@file:Suppress("TooGenericExceptionCaught")

package com.wire.crypto

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.ByteArray

/** Wrap a `CoreCrypto` instance in a `CoreCryptoClient` instance. Should largely be invisible to end-users. */
fun CoreCryptoFfi.lift() = CoreCrypto(this)

/**
 * A high-level wrapper around a CoreCrypto client as emitted by Uniffi.
 *
 * This wrapper should be largely transparent to end users. It exists to improve the
 * callback interfaces: `.transaction(...)`, `.registerFooObserver(...)`, etc.
 */
class CoreCrypto(private val cc: CoreCryptoFfi) {
    companion object {
        /** Opens a core crypto client with the specified database, previously instantiated via [openDatabase].  */
        suspend operator fun invoke(
            database: Database,
        ) =
            CoreCrypto(coreCryptoNew(database))

        /**
         * Instantiate a history client.
         *
         * This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
         * Other use is a logic error.
         */
        suspend fun historyClient(historySecret: HistorySecret) = CoreCrypto(coreCryptoHistoryClient(historySecret))

        /**
         * @returns The last resort PreKey id
         */
        @Throws(CoreCryptoException::class)
        fun proteusLastResortPrekeyId() = proteusLastResortPrekeyIdFfi()

        /**
         * Hex-encoded fingerprint of the given prekey
         *
         * @param prekey - the prekey bundle to get the fingerprint from
         * @returns Hex-encoded public key string
         **/
        @Throws(CoreCryptoException::class)
        fun proteusFingerprintPrekeybundle(
            prekey: kotlin.ByteArray
        ) = proteusFingerprintPrekeybundleFfi(prekey)
    }

    /**
     * Starts a [NonCancellable] transaction in Core Crypto. If the callback succeeds, it will be committed,
     * otherwise, every operation performed with the context will be discarded.
     *
     * Check [Uniffi's documentation](https://mozilla.github.io/uniffi-rs/latest/futures.html#cancelling-async-code)
     * about async code, that mentions that it does not support cancellation. So we go around it by not cancelling
     * it either.
     * @param R the type returned by the transaction block
     * @param block the function to be executed within the transaction context.
     *              A [CoreCryptoContext] will be given as parameter to this function.
     *
     * @return the return of the function passed as parameter
     */
    @Suppress("unchecked_cast")
    suspend fun <R> transaction(block: suspend (context: CoreCryptoContext) -> R): R = withContext(NonCancellable) {
        var result: R? = null
        var error: Throwable? = null
        try {
            this@CoreCrypto.cc.transaction(object : CoreCryptoCommand {
                override suspend fun execute(context: CoreCryptoContext) {
                    try {
                        result = block(context)
                    } catch (e: Throwable) {
                        // We want to catch the error before it gets wrapped by core crypto.
                        error = e
                        // This is to tell core crypto that there was an error inside the transaction.
                        throw e
                    }
                }
            })
        } catch (e: Throwable) {
            // We prefer the closure error if it's available since the transaction won't include it
            error = error ?: e
        }
        if (error != null) {
            throw error as Throwable
        }

        // Since we know that the transaction will either succeed or throw it's safe to do an unchecked cast here
        return@withContext result as R
    }

    /**
     * Register an Epoch Observer which will be notified every time a conversation's epoch changes.
     *
     * This function should be called 0 or 1 times in the lifetime of CoreCrypto, regardless of the number of transactions.
     */
    suspend fun registerEpochObserver(scope: CoroutineScope, epochObserver: EpochObserver) {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        val observerIndirector = object : EpochObserver {
            override suspend fun epochChanged(conversationId: ConversationId, epoch: kotlin.ULong) {
                scope.launch { epochObserver.epochChanged(conversationId, epoch) }
            }
        }
        return cc.registerEpochObserver(observerIndirector)
    }

    /**
     * Register a History Observer which will be notified every time a new history client is created.
     *
     * This function should be called 0 or 1 times in the lifetime of CoreCrypto, regardless of the number of transactions.
     */
    suspend fun registerHistoryObserver(scope: CoroutineScope, historyObserver: HistoryObserver) {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        val observerIndirector = object : HistoryObserver {
            override suspend fun historyClientCreated(
                conversationId: ConversationId,
                secret: HistorySecret
            ) {
                scope.launch { historyObserver.historyClientCreated(conversationId, secret) }
            }
        }
        return cc.registerHistoryObserver(observerIndirector)
    }

    /**
     * See [CoreCryptoContext.isHistorySharingEnabled]
     *
     * @param conversationId conversation identifier
     * @return true if history sharing is enabled
     */
    suspend fun isHistorySharingEnabled(conversationId: ConversationId): Boolean = cc.isHistorySharingEnabled(conversationId)

    /**
     * Closes this [CoreCrypto] instance and deallocates all loaded resources.
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in Kotlin, so you'll get errors instead!
     */
    fun close() {
        cc.close()
    }
}
