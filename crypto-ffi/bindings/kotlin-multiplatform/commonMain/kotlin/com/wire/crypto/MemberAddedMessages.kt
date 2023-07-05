package com.wire.crypto


import okio.Buffer

data class MemberAddedMessages (
    var `commit`: List<UByte>, 
    var `welcome`: List<UByte>, 
    var `publicGroupState`: PublicGroupStateBundle
) {
    
}

object FfiConverterTypeMemberAddedMessages: FfiConverterRustBuffer<MemberAddedMessages> {
    override fun read(buf: Buffer): MemberAddedMessages {
        return MemberAddedMessages(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
            FfiConverterTypePublicGroupStateBundle.read(buf),
        )
    }

    override fun allocationSize(value: MemberAddedMessages) = (
            FfiConverterSequenceUByte.allocationSize(value.`commit`) +
            FfiConverterSequenceUByte.allocationSize(value.`welcome`) +
            FfiConverterTypePublicGroupStateBundle.allocationSize(value.`publicGroupState`)
    )

    override fun write(value: MemberAddedMessages, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`commit`, buf)
            FfiConverterSequenceUByte.write(value.`welcome`, buf)
            FfiConverterTypePublicGroupStateBundle.write(value.`publicGroupState`, buf)
    }
}