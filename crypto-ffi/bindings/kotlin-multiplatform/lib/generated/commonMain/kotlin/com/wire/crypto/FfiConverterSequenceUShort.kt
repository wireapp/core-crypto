package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceUShort: FfiConverterRustBuffer<List<UShort>> {
    override fun read(buf: Buffer): List<UShort> {
        val len = buf.readInt()
        return List<UShort>(len) {
            FfiConverterUShort.read(buf)
        }
    }

    override fun allocationSize(value: List<UShort>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterUShort.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<UShort>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterUShort.write(it, buf)
        }
    }
}