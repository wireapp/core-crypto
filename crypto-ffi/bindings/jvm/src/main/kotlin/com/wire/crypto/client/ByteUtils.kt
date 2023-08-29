package com.wire.crypto.client

fun String.toByteArray() = encodeToByteArray()

fun ByteArray.toHex(): String = joinToString(separator = "") { b -> "%02x".format(b) }