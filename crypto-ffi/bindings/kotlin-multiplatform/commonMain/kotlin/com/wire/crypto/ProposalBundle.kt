package com.wire.crypto


import okio.Buffer

data class ProposalBundle (
    var `proposal`: List<UByte>, 
    var `proposalRef`: List<UByte>
) {
    
}

object FfiConverterTypeProposalBundle: FfiConverterRustBuffer<ProposalBundle> {
    override fun read(buf: Buffer): ProposalBundle {
        return ProposalBundle(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
        )
    }

    override fun allocationSize(value: ProposalBundle) = (
            FfiConverterSequenceUByte.allocationSize(value.`proposal`) +
            FfiConverterSequenceUByte.allocationSize(value.`proposalRef`)
    )

    override fun write(value: ProposalBundle, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`proposal`, buf)
            FfiConverterSequenceUByte.write(value.`proposalRef`, buf)
    }
}