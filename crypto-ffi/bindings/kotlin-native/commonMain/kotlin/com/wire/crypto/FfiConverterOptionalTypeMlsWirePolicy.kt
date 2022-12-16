package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeMlsWirePolicy: FfiConverterRustBuffer<MlsWirePolicy?> {
    override fun read(buf: Buffer): MlsWirePolicy? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeMlsWirePolicy.read(buf)
    }

    override fun allocationSize(value: MlsWirePolicy?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeMlsWirePolicy.allocationSize(value)
        }
    }

    override fun write(value: MlsWirePolicy?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeMlsWirePolicy.write(value, buf)
        }
    }
}