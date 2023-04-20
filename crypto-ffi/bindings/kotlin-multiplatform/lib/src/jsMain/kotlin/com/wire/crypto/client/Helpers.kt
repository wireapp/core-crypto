package com.wire.crypto.client

import org.khronos.webgl.Int8Array
import org.khronos.webgl.Uint8Array

fun Uint8Array.toByteArray() = this.unsafeCast<ByteArray>() //Int8Array(buffer, byteOffset, length).unsafeCast<ByteArray>()
fun ByteArray.toUint8Array() = this.unsafeCast<Uint8Array>()

fun String.toUint8Array() = this.unsafeCast<Uint8Array>()
