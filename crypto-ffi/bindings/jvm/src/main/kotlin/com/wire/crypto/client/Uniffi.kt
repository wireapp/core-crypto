package com.wire.crypto.client

interface FfiType<K, R> {
    val value: K
    fun lower(): R
}

// TODO: this should go away at some point when all the remaining Uniffi issues have been fixed and everything is a [ByteArray]
interface Uniffi023 : FfiType<ByteArray, List<UByte>> {
    override fun lower() = value.map { it.toUByte() }
}

interface Uniffi : FfiType<ByteArray, ByteArray> {
    override fun lower() = value
}