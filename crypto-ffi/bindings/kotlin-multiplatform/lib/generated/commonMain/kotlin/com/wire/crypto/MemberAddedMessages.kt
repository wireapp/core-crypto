package com.wire.crypto


import okio.Buffer

data class MemberAddedMessages (
    var `commit`: List<UByte>, 
    var `welcome`: List<UByte>, 
    var `groupInfo`: GroupInfoBundle
) {
    
}

object FfiConverterTypeMemberAddedMessages: FfiConverterRustBuffer<MemberAddedMessages> {
    override fun read(buf: Buffer): MemberAddedMessages {
        return MemberAddedMessages(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
            FfiConverterTypeGroupInfoBundle.read(buf),
        )
    }

    override fun allocationSize(value: MemberAddedMessages) = (
            FfiConverterSequenceUByte.allocationSize(value.`commit`) +
            FfiConverterSequenceUByte.allocationSize(value.`welcome`) +
            FfiConverterTypeGroupInfoBundle.allocationSize(value.`groupInfo`)
    )

    override fun write(value: MemberAddedMessages, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`commit`, buf)
            FfiConverterSequenceUByte.write(value.`welcome`, buf)
            FfiConverterTypeGroupInfoBundle.write(value.`groupInfo`, buf)
    }
}