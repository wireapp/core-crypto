package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeClientId: FfiConverterRustBuffer<ClientId?> {
    override fun read(buf: Buffer): ClientId? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeClientId.read(buf)
    }

    override fun allocationSize(value: ClientId?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeClientId.allocationSize(value)
        }
    }

    override fun write(value: ClientId?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeClientId.write(value, buf)
        }
    }
}