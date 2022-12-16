package com.wire.crypto

import okio.Buffer

object FfiConverterOptionalTypeCommitBundle: FfiConverterRustBuffer<CommitBundle?> {
    override fun read(buf: Buffer): CommitBundle? {
        if (buf.readByte().toInt() == 0) {
            return null
        }
        return FfiConverterTypeCommitBundle.read(buf)
    }

    override fun allocationSize(value: CommitBundle?): Int {
        if (value == null) {
            return 1
        } else {
            return 1 + FfiConverterTypeCommitBundle.allocationSize(value)
        }
    }

    override fun write(value: CommitBundle?, buf: Buffer) {
        if (value == null) {
            buf.writeByte(0)
        } else {
            buf.writeByte(1)
            FfiConverterTypeCommitBundle.write(value, buf)
        }
    }
}