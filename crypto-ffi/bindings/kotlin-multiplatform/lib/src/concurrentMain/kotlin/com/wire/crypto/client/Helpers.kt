package com.wire.crypto.client

fun ByteArray.toUByteList(): List<UByte> = this.asUByteArray().asList()
fun String.toUByteList(): List<UByte> = this.encodeToByteArray().asUByteArray().asList()
fun List<UByte>.toByteArray() = this.toUByteArray().asByteArray()
