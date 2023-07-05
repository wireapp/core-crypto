package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeWireIdentity: FfiConverterRustBuffer<WireIdentity?> {
    override fun read(buf: Buffer): WireIdentity? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeWireIdentity.read(buf)
    }

    override fun allocationSize(value: WireIdentity?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeWireIdentity.allocationSize(value)
        }
    }

    override fun write(value: WireIdentity?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeWireIdentity.write(value, buf)
        }
    }
}