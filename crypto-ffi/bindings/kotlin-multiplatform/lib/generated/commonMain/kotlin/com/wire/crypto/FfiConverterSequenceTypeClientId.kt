package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceTypeClientId: FfiConverterRustBuffer<List<ClientId>> {
    override fun read(buf: Buffer): List<ClientId> {
        val len = buf.readInt()
        return List<ClientId>(len) {
            FfiConverterTypeClientId.read(buf)
        }
    }

    override fun allocationSize(value: List<ClientId>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterTypeClientId.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<ClientId>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterTypeClientId.write(it, buf)
        }
    }
}