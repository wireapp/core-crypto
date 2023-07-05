package com.wire.crypto

actual fun ForeignCallbackTypeCoreCryptoCallbacks.toForeignCallback() : ForeignCallback =
    NativeCallback(this::invoke)