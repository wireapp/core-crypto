package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceUByte: FfiConverterRustBuffer<List<UByte>> {
    override fun read(buf: Buffer): List<UByte> {
        val len = buf.readInt()
        return List<UByte>(len) {
            FfiConverterUByte.read(buf)
        }
    }

    override fun allocationSize(value: List<UByte>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterUByte.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<UByte>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterUByte.write(it, buf)
        }
    }
}