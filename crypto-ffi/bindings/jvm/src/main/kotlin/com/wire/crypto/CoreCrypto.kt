@file:Suppress("TooGenericExceptionCaught")

package com.wire.crypto

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

typealias EnrollmentHandle = ByteArray

/** Represents a CoreCrypto database key */
@JvmInline
value class DatabaseKey(internal val bytes: ByteArray)

/**
 * Updates the key of the CoreCrypto database.
 * To be used only once, when moving from CoreCrypto <= 5.x to CoreCrypto 6.x.
 * @param name path to the database file
 * @param oldKey the old key
 * @param newKey the new key
 */
suspend fun migrateDatabaseKeyTypeToBytes(name: String, oldKey: String, newKey: DatabaseKey) {
    return com.wire.crypto.uniffi.migrateDbKeyTypeToBytes(name, oldKey, newKey.bytes)
}

/**
 * An `EpochObserver` is notified whenever a conversation's epoch changes.
 */
public interface EpochObserver {
    /**
     * This function will be called every time a conversation's epoch changes.
     *
     * The `epoch` parameter is the new epoch.
     *
     * <div class="warning">
     * This function must not block! Foreign implementors of this inteface can
     * spawn a task indirecting the notification, or (unblocking) send the notification
     * on some kind of channel, or anything else, as long as the operation completes
     * quickly.
     * </div>
     *
     * Though the signature includes an error type, that error is only present because
     * it is required by `uniffi` in order to handle panics. This function should suppress
     * and ignore internal errors instead of propagating them, to the maximum extent possible.
     */
    suspend fun epochChanged(conversationId: kotlin.ByteArray, epoch: kotlin.ULong)
}

/**
 * Defines the log level for CoreCrypto
 */
enum class CoreCryptoLogLevel {
    /** OFF */
    OFF,

    /** TRACE */
    TRACE,

    /** DEBUG */
    DEBUG,

    /** INFO */
    INFO,

    /** WARN */
    WARN,

    /** ERROR */
    ERROR
}

internal fun CoreCryptoLogLevel.lower() = when (this) {
    CoreCryptoLogLevel.OFF -> com.wire.crypto.uniffi.CoreCryptoLogLevel.OFF
    CoreCryptoLogLevel.TRACE -> com.wire.crypto.uniffi.CoreCryptoLogLevel.TRACE
    CoreCryptoLogLevel.DEBUG -> com.wire.crypto.uniffi.CoreCryptoLogLevel.DEBUG
    CoreCryptoLogLevel.INFO -> com.wire.crypto.uniffi.CoreCryptoLogLevel.INFO
    CoreCryptoLogLevel.WARN -> com.wire.crypto.uniffi.CoreCryptoLogLevel.WARN
    CoreCryptoLogLevel.ERROR -> com.wire.crypto.uniffi.CoreCryptoLogLevel.ERROR
}

internal fun com.wire.crypto.uniffi.CoreCryptoLogLevel.lift() = when (this) {
    com.wire.crypto.uniffi.CoreCryptoLogLevel.OFF -> CoreCryptoLogLevel.OFF
    com.wire.crypto.uniffi.CoreCryptoLogLevel.TRACE -> CoreCryptoLogLevel.TRACE
    com.wire.crypto.uniffi.CoreCryptoLogLevel.DEBUG -> CoreCryptoLogLevel.DEBUG
    com.wire.crypto.uniffi.CoreCryptoLogLevel.INFO -> CoreCryptoLogLevel.INFO
    com.wire.crypto.uniffi.CoreCryptoLogLevel.WARN -> CoreCryptoLogLevel.WARN
    com.wire.crypto.uniffi.CoreCryptoLogLevel.ERROR -> CoreCryptoLogLevel.ERROR
}

/** The logger interface */
interface CoreCryptoLogger {
    /**
     *  Core Crypto will call this method whenever it needs to log a message.
     */
    fun log(level: CoreCryptoLogLevel, message: String, context: String?)
}

/**
 * Initializes the logging inside Core Crypto. Not required to be called and by default there will be no logging.
 *
 * @param logger a callback to implement the platform specific logging. It will receive the string with the log text from Core Crypto
 **/
fun setLogger(logger: CoreCryptoLogger) {
    com.wire.crypto.uniffi.setLoggerOnly(object : com.wire.crypto.uniffi.CoreCryptoLogger {
        override fun log(level: com.wire.crypto.uniffi.CoreCryptoLogLevel, message: String, context: String?) {
            logger.log(level.lift(), message, context)
        }
    })
}

/**
 * Set maximum log level of logs which are forwarded to the [CoreCryptoLogger].
 *
 * @param level the max level that should be logged, by default it will be WARN
 */
fun setMaxLogLevel(level: CoreCryptoLogLevel) {
    com.wire.crypto.uniffi.setMaxLogLevel(level.lower())
}

/** The type representing a CoreCrypto client */
class CoreCrypto(private val cc: com.wire.crypto.uniffi.CoreCrypto) {
    companion object {
        internal const val DEFAULT_NB_KEY_PACKAGE: UInt = 100U

        /** Opens an existing core crypto client or creates a new one if one doesn't exist at the `keystore` path */
        suspend operator fun invoke(
            keystore: String,
            databaseKey: DatabaseKey
        ): CoreCrypto {
            val cc = com.wire.crypto.uniffi.coreCryptoDeferredInit(keystore, databaseKey.bytes, null)
            return CoreCrypto(cc)
        }

        /**
         * Instantiate a history client.
         *
         * This client exposes the full interface of `CoreCrypto`, but it should only be used to decrypt messages.
         * Other use is a logic error.
         */
        suspend fun historyClient(historySecret: kotlin.ByteArray): CoreCrypto {
            val cc = com.wire.crypto.uniffi.coreCryptoHistoryClient(historySecret)
            return CoreCrypto(cc)
        }
    }

    internal fun lower() = cc

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
            this@CoreCrypto.cc.transaction(object : com.wire.crypto.uniffi.CoreCryptoCommand {
                override suspend fun execute(context: com.wire.crypto.uniffi.CoreCryptoContext) {
                    try {
                        result = block(CoreCryptoContext(context))
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

    /** Provide an implementation of the MlsTransport interface.
     * See [MlsTransport].
     * @param transport the transport to be used
     */
    suspend fun provideTransport(transport: MlsTransport) {
        cc.provideTransport(object : com.wire.crypto.uniffi.MlsTransport {
            override suspend fun sendCommitBundle(
                commitBundle: com.wire.crypto.uniffi.CommitBundle
            ): com.wire.crypto.uniffi.MlsTransportResponse {
                return transport.sendCommitBundle(commitBundle.lift()).lower()
            }

            override suspend fun sendMessage(mlsMessage: ByteArray): com.wire.crypto.uniffi.MlsTransportResponse {
                return transport.sendMessage(mlsMessage).lower()
            }
        })
    }

    /**
     * Register an Epoch Observer which will be notified every time a conversation's epoch changes.
     *
     * This function should be called 0 or 1 times in the lifetime of CoreCrypto, regardless of the number of transactions.
     */
    suspend fun registerEpochObserver(scope: CoroutineScope, epochObserver: EpochObserver) {
        // we want to wrap the observer here to provide async indirection, so that no matter what
        // the observer that makes its way to the Rust side of things doesn't end up blocking
        val observerIndirector = object : com.wire.crypto.uniffi.EpochObserver {
            override suspend fun epochChanged(conversationId: kotlin.ByteArray, epoch: kotlin.ULong) {
                scope.launch { epochObserver.epochChanged(conversationId, epoch) }
            }
        }
        return wrapException {
            cc.registerEpochObserver(observerIndirector)
        }
    }

    /**
     * Closes this [CoreCrypto] instance and deallocates all loaded resources.
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in Kotlin, so you'll get errors instead!
     */
    fun close() {
        cc.close()
    }
}
