package com.wire.crypto

import okio.Buffer

object FfiConverterSequenceTypeProposalBundle: FfiConverterRustBuffer<List<ProposalBundle>> {
    override fun read(buf: Buffer): List<ProposalBundle> {
        val len = buf.readInt()
        return List<ProposalBundle>(len) {
            FfiConverterTypeProposalBundle.read(buf)
        }
    }

    override fun allocationSize(value: List<ProposalBundle>): Int {
        val sizeForLength = 4
        val sizeForItems = value.map { FfiConverterTypeProposalBundle.allocationSize(it) }.sum()
        return sizeForLength + sizeForItems
    }

    override fun write(value: List<ProposalBundle>, buf: Buffer) {
        buf.writeInt(value.size)
        value.forEach {
            FfiConverterTypeProposalBundle.write(it, buf)
        }
    }
}