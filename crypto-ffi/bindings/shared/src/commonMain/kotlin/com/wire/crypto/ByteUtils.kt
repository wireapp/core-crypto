package com.wire.crypto

internal fun String.toByteArray() = encodeToByteArray()

// this opt-in can be removed once the project updates to Kotlin 2.2 or higher
@OptIn(ExperimentalStdlibApi::class)
internal fun ByteArray.toHex(): String = toHexString()
