package com.wire.crypto

/** Wrap a [CoreCryptoContextFfi] instance in a [CoreCryptoContext] instance. */
fun CoreCryptoContextFfi.lift() = CoreCryptoContext(this)

/** A high-level wrapper around a transaction context as emitted by UniFFI. */
class CoreCryptoContext(private val context: CoreCryptoContextFfi) : CoreCryptoContextFfiInterface by context {
    /**
     * Creates a new Proteus prekey with the given ID and returns its CBOR-serialized bundle.
     *
     * Fails if the ID is already in use. Prekeys are not replaceable: the ID has been published to
     * peers in a bundle, and overwriting it would strand anyone still holding that bundle. Use
     * [proteusNewPrekeyAuto] to have a free ID chosen instead.
     *
     * Warning: the Proteus client must be initialized with [proteusInit] first or an error will be returned.
     */
    @Deprecated("Use proteusNewPrekeyAuto() instead.")
    @Throws(CoreCryptoException::class)
    override suspend fun proteusNewPrekey(prekeyId: UShort): ByteArray = context.proteusNewPrekey(prekeyId)

    // `close()` isn't containted in CoreCryptoContextFfiInterface, so we need to wrap it manually.

    /** Closes this context and deallocates all loaded resources. It cannot be used afterwards. */
    fun close() {
        context.close()
    }
}
