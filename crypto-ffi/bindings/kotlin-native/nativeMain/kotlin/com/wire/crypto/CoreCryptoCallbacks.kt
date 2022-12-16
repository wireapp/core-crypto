package com.wire.crypto

import kotlinx.cinterop.staticCFunction

actual fun ForeignCallbackTypeCoreCryptoCallbacks.toForeignCallback() : ForeignCallback =
    staticCFunction{ handle: Handle, method: Int, args: RustBuffer, outBuf: RustBufferPointer?->
        ForeignCallbackTypeCoreCryptoCallbacks.invoke(handle,method,args, requireNotNull( outBuf))
    }