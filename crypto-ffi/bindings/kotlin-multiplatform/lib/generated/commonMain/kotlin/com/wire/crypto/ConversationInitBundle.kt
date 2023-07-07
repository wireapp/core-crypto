package com.wire.crypto


import okio.Buffer

data class ConversationInitBundle (
    var `conversationId`: List<UByte>, 
    var `commit`: List<UByte>, 
    var `groupInfo`: GroupInfoBundle
) {
    
}

object FfiConverterTypeConversationInitBundle: FfiConverterRustBuffer<ConversationInitBundle> {
    override fun read(buf: Buffer): ConversationInitBundle {
        return ConversationInitBundle(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
            FfiConverterTypeGroupInfoBundle.read(buf),
        )
    }

    override fun allocationSize(value: ConversationInitBundle) = (
            FfiConverterSequenceUByte.allocationSize(value.`conversationId`) +
            FfiConverterSequenceUByte.allocationSize(value.`commit`) +
            FfiConverterTypeGroupInfoBundle.allocationSize(value.`groupInfo`)
    )

    override fun write(value: ConversationInitBundle, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`conversationId`, buf)
            FfiConverterSequenceUByte.write(value.`commit`, buf)
            FfiConverterTypeGroupInfoBundle.write(value.`groupInfo`, buf)
    }
}