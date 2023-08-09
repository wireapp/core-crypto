package com.wire.crypto.client

fun ByteArray.toUByteList(): List<UByte> = map { it.toUByte() }

@OptIn(ExperimentalUnsignedTypes::class)
fun String.toUByteList(): List<UByte> = toByteArray().asUByteArray().asList()

@OptIn(ExperimentalUnsignedTypes::class)
fun List<UByte>.toByteArray() = toUByteArray().asByteArray()

fun String.toByteArray() = encodeToByteArray()

fun ByteArray.toHex(): String = joinToString(separator = "") { b -> "%02x".format(b) }
fun List<UByte>.toHex(): String = toByteArray().toHex()
fun String.toHex(): String = encodeToByteArray().toHex()