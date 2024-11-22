package com.wire.crypto.client

interface FfiType<K, R> {
    val value: K

    fun lower(): R
}

interface Uniffi : FfiType<ByteArray, ByteArray> {
    override fun lower() = value
}
