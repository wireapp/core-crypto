package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalSequenceTypeClientId: FfiConverterRustBuffer<List<ClientId>?> {
    override fun read(buf: Buffer): List<ClientId>? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterSequenceTypeClientId.read(buf)
    }

    override fun allocationSize(value: List<ClientId>?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterSequenceTypeClientId.allocationSize(value)
        }
    }

    override fun write(value: List<ClientId>?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterSequenceTypeClientId.write(value, buf)
        }
    }
}