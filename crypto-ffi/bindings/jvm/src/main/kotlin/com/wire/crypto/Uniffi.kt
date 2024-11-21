package com.wire.crypto

interface FfiType<K, R> {
    val value: K

    fun lower(): R
}

interface Uniffi : FfiType<ByteArray, ByteArray> {
    override fun lower() = value
}
