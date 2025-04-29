package com.wire.crypto

internal fun String.toByteArray() = encodeToByteArray()

internal fun ByteArray.toHex(): String = joinToString(separator = "") { b -> "%02x".format(b) }
