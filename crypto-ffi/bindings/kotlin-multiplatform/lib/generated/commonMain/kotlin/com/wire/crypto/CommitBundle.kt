package com.wire.crypto


import okio.Buffer

data class CommitBundle (
    var `welcome`: List<UByte>?, 
    var `commit`: List<UByte>, 
    var `publicGroupState`: PublicGroupStateBundle
) {
    
}

object FfiConverterTypeCommitBundle: FfiConverterRustBuffer<CommitBundle> {
    override fun read(buf: Buffer): CommitBundle {
        return CommitBundle(
            FfiConverterOptionalSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
            FfiConverterTypePublicGroupStateBundle.read(buf),
        )
    }

    override fun allocationSize(value: CommitBundle) = (
            FfiConverterOptionalSequenceUByte.allocationSize(value.`welcome`) +
            FfiConverterSequenceUByte.allocationSize(value.`commit`) +
            FfiConverterTypePublicGroupStateBundle.allocationSize(value.`publicGroupState`)
    )

    override fun write(value: CommitBundle, buf: Buffer) {
            FfiConverterOptionalSequenceUByte.write(value.`welcome`, buf)
            FfiConverterSequenceUByte.write(value.`commit`, buf)
            FfiConverterTypePublicGroupStateBundle.write(value.`publicGroupState`, buf)
    }
}