package com.wire.crypto

internal interface FfiType<K, R> {
    val value: K

    fun lower(): R
}

internal interface Uniffi : FfiType<ByteArray, ByteArray> {
    override fun lower() = value
}
