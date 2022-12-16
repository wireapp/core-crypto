package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceSequenceUByte: FfiConverterRustBuffer<List<List<UByte>>> {
    override fun read(buf: Buffer): List<List<UByte>> {
        val len = buf.readInt()
        return List<List<UByte>>(len) {
            FfiConverterSequenceUByte.read(buf)
        }
    }

    override fun allocationSize(value: List<List<UByte>>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterSequenceUByte.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<List<UByte>>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterSequenceUByte.write(it, buf)
        }
    }
}