package com.wire.crypto

import okio.Buffer
object FfiConverterMapStringListUByte: FfiConverterRustBuffer<Map<String, List<UByte>>> {
    override fun read(buf: Buffer): Map<String, List<UByte>> {
        val items : MutableMap<String, List<UByte>> = mutableMapOf()
        val len = buf.readInt()
        repeat(len) {
            val k = FfiConverterString.read(buf)
            val v = FfiConverterSequenceUByte.read(buf)
            items[k] = v
        }
        return items
    }

    override fun allocationSize(value: Map<String, List<UByte>>): Int {
        val spaceForMapSize = 4
        val spaceForChildren = value.map { (k, v) ->
            FfiConverterString.allocationSize(k) +
            FfiConverterSequenceUByte.allocationSize(v)
        }.sum()
        return spaceForMapSize + spaceForChildren
    }

    override fun write(value: Map<String, List<UByte>>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach { (k, v) ->
            FfiConverterString.write(k, buf)
            FfiConverterSequenceUByte.write(v, buf)
        }
    }
}