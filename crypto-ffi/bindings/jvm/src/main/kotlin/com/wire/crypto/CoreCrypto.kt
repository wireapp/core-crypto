package com.wire.crypto

import com.wire.crypto.uniffi.CoreCryptoLogLevel

typealias EnrollmentHandle = ByteArray

/**
 * Defines the log level for a CoreCrypto
 */
enum class CoreCryptoLogLevel {
    OFF,
    TRACE,
    DEBUG,
    INFO,
    WARN,
    ERROR;
}

internal fun CoreCryptoLogLevel.lower() = when (this) {
    CoreCryptoLogLevel.OFF -> com.wire.crypto.uniffi.CoreCryptoLogLevel.OFF
    CoreCryptoLogLevel.TRACE -> com.wire.crypto.uniffi.CoreCryptoLogLevel.TRACE
    CoreCryptoLogLevel.DEBUG -> com.wire.crypto.uniffi.CoreCryptoLogLevel.DEBUG
    CoreCryptoLogLevel.INFO -> com.wire.crypto.uniffi.CoreCryptoLogLevel.INFO
    CoreCryptoLogLevel.WARN -> com.wire.crypto.uniffi.CoreCryptoLogLevel.WARN
    CoreCryptoLogLevel.ERROR -> com.wire.crypto.uniffi.CoreCryptoLogLevel.ERROR
}

interface CoreCryptoLogger: com.wire.crypto.uniffi.CoreCryptoLogger {

    /**
     *  Core Crypto will call this method whenever it needs to log a message.
     */
    override fun log(level: CoreCryptoLogLevel, message: String, `context`: String?)
}

/**
 * Initializes the logging inside Core Crypto. Not required to be called and by default there will be no logging.
 *
 * @param logger a callback to implement the platform specific logging. It will receive the string with the log text from Core Crypto
 **/
fun setLogger(logger: CoreCryptoLogger) {
    com.wire.crypto.uniffi.setLoggerOnly(logger)
}

/**
 * Set maximum log level of logs which are forwarded to the [CoreCryptoLogger].
 *
 * @param  level the max level that should be logged, by default it will be WARN
 */
fun setMaxLogLevel(level: CoreCryptoLogLevel) {
    com.wire.crypto.uniffi.setMaxLogLevel(level.lower())
}

class CoreCrypto(private val cc: com.wire.crypto.uniffi.CoreCrypto) {

    companion object {
        internal const val DEFAULT_NB_KEY_PACKAGE: UInt = 100U

        suspend operator fun invoke(
            keystore: String,
            databaseKey: String
        ): CoreCrypto {
            val cc = com.wire.crypto.uniffi.coreCryptoDeferredInit(keystore, databaseKey)
            cc.setCallbacks(Callbacks())
            return CoreCrypto(cc)
        }
    }

    internal fun lower() = cc

    /**
     * Starts a transaction in Core Crypto. If the callback succeeds, it will be committed, otherwise, every operation
     * performed with the context will be discarded.
     *
     * @param block the function to be executed within the transaction context. A [CoreCryptoContext] will be given as parameter to this function
     *
     * @return the return of the function passed as parameter
     */
    @Suppress("unchecked_cast")
    suspend fun <R> transaction(block: suspend (context: CoreCryptoContext) -> R): R {
        var result: R? = null
        var error: Throwable? = null
        try {
            this.cc.transaction(object : com.wire.crypto.uniffi.CoreCryptoCommand {
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
            // Catch the wrapped error, which we don't need, because we caught the original error above.
        } catch (_: Throwable) { }
        if (error != null) {
            throw error as Throwable
        }

        // Since we know that transaction will either run or throw it's safe to do unchecked cast here
        return result as R
    }

    /**
     * Initialise [CoreCrypto] to be used with proteus.
     *
     * All proteus related methods will fail until this function is called.
     */
    suspend fun proteusInit() {
        cc.proteusInit()
    }

    /**
     * Closes this [CoreCrypto] instance and deallocates all loaded resources.
     *
     * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in Kotlin, so you'll get errors instead!
     */
    fun close() {
        cc.close()
    }

    /**
     * Wipes all in-memory and persisted data associated with this [CoreCrypto] instance.
     *
     * * **CAUTION**: This {@link CoreCrypto} instance won't be usable after a call to this method, but there's no way to express this requirement in Kotlin, so you'll get errors instead!
     */
    suspend fun wipe() {
        cc.wipe()
    }
}

private class Callbacks : com.wire.crypto.uniffi.CoreCryptoCallbacks {

    override suspend fun authorize(conversationId: ByteArray, clientId: ByteArray): Boolean = true

    override suspend fun userAuthorize(
        conversationId: ByteArray,
        externalClientId: ByteArray,
        existingClients: List<ByteArray>
    ): Boolean = true

    override suspend fun clientIsExistingGroupUser(
        conversationId: ByteArray,
        clientId: ByteArray,
        existingClients: List<ByteArray>,
        parentConversationClients: List<ByteArray>?
    ): Boolean = true
}
