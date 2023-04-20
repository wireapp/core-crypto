package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceTypeInvitee: FfiConverterRustBuffer<List<Invitee>> {
    override fun read(buf: Buffer): List<Invitee> {
        val len = buf.readInt()
        return List<Invitee>(len) {
            FfiConverterTypeInvitee.read(buf)
        }
    }

    override fun allocationSize(value: List<Invitee>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterTypeInvitee.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<Invitee>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterTypeInvitee.write(it, buf)
        }
    }
}