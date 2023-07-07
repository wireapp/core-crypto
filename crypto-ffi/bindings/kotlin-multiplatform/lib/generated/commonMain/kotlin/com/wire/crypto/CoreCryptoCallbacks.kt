package com.wire.crypto



interface CoreCryptoCallbacks {
    fun `authorize`(`conversationId`: ConversationId, `clientId`: ClientId): Boolean
    fun `userAuthorize`(`conversationId`: ConversationId, `externalClientId`: ClientId, `existingClients`: List<ClientId>): Boolean
    fun `clientIsExistingGroupUser`(`conversationId`: ConversationId, `clientId`: ClientId, `existingClients`: List<ClientId>, `parentConversationClients`: List<ClientId>?): Boolean
    
}

object ForeignCallbackTypeCoreCryptoCallbacks {
    @Suppress("TooGenericExceptionCaught")
    fun invoke(handle: Handle, method: Int, args: RustBuffer, outBuf: RustBufferPointer): Int {
        val cb = FfiConverterTypeCoreCryptoCallbacks.lift(handle)
        return when (method) {
            IDX_CALLBACK_FREE -> {
                FfiConverterTypeCoreCryptoCallbacks.drop(handle)
                0
            }
            1 -> {
                try {
                    val buffer = this.`invokeAuthorize`(cb, args)
                    // Success
                    outBuf.setValue(buffer)
                    1
                } catch (e: Throwable) {
                    try {
                        outBuf.setValue(FfiConverterString.lower(e.toString()))
                    } catch (e: Throwable) {
                    }
                    -1
                }
            }
            2 -> {
                try {
                    val buffer = this.`invokeUserAuthorize`(cb, args)
                    // Success
                    outBuf.setValue(buffer)
                    1
                } catch (e: Throwable) {
                    try {
                        outBuf.setValue(FfiConverterString.lower(e.toString()))
                    } catch (e: Throwable) {
                    }
                    -1
                }
            }
            3 -> {
                try {
                    val buffer = this.`invokeClientIsExistingGroupUser`(cb, args)
                    // Success
                    outBuf.setValue(buffer)
                    1
                } catch (e: Throwable) {
                    try {
                        outBuf.setValue(FfiConverterString.lower(e.toString()))
                    } catch (e: Throwable) {
                    }
                    -1
                }
            }
            
            else -> {
                try {
                    outBuf.setValue(FfiConverterString.lower("Invalid Callback index"))
                } catch (e: Throwable) {
                }
                -1
            }
        }
    }

    
    private fun `invokeAuthorize`(kotlinCallbackInterface: CoreCryptoCallbacks, args: RustBuffer): RustBuffer =
        try {
            val buf = checkNotNull(args.toBuffer()) { "No Buffer in RustBuffer; this is a Uniffi bug" }
            kotlinCallbackInterface.`authorize`(
                    FfiConverterTypeConversationId.read(buf), 
                    FfiConverterTypeClientId.read(buf)
                    )
            .let {
                    FfiConverterBoolean.lowerIntoRustBuffer(it)
                }} finally {
            args.free()
        }

    
    private fun `invokeUserAuthorize`(kotlinCallbackInterface: CoreCryptoCallbacks, args: RustBuffer): RustBuffer =
        try {
            val buf = checkNotNull(args.toBuffer()) { "No Buffer in RustBuffer; this is a Uniffi bug" }
            kotlinCallbackInterface.`userAuthorize`(
                    FfiConverterTypeConversationId.read(buf), 
                    FfiConverterTypeClientId.read(buf), 
                    FfiConverterSequenceTypeClientId.read(buf)
                    )
            .let {
                    FfiConverterBoolean.lowerIntoRustBuffer(it)
                }} finally {
            args.free()
        }

    
    private fun `invokeClientIsExistingGroupUser`(kotlinCallbackInterface: CoreCryptoCallbacks, args: RustBuffer): RustBuffer =
        try {
            val buf = checkNotNull(args.toBuffer()) { "No Buffer in RustBuffer; this is a Uniffi bug" }
            kotlinCallbackInterface.`clientIsExistingGroupUser`(
                    FfiConverterTypeConversationId.read(buf), 
                    FfiConverterTypeClientId.read(buf), 
                    FfiConverterSequenceTypeClientId.read(buf), 
                    FfiConverterOptionalSequenceTypeClientId.read(buf)
                    )
            .let {
                    FfiConverterBoolean.lowerIntoRustBuffer(it)
                }} finally {
            args.free()
        }

    
}

object FfiConverterTypeCoreCryptoCallbacks: FfiConverterCallbackInterface<CoreCryptoCallbacks>() {
    override fun register(lib: UniFFILib) {
        rustCall() { status ->
            lib.ffi_CoreCrypto_fbd8_CoreCryptoCallbacks_init_callback(ForeignCallbackTypeCoreCryptoCallbacks.toForeignCallback(), status)
        }
    }
}

expect fun ForeignCallbackTypeCoreCryptoCallbacks.toForeignCallback() : ForeignCallback