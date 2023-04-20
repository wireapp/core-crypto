package com.wire.crypto


import okio.Buffer

data class ConversationInitBundle (
    var `conversationId`: List<UByte>, 
    var `commit`: List<UByte>, 
    var `publicGroupState`: PublicGroupStateBundle
) {
    
}

object FfiConverterTypeConversationInitBundle: FfiConverterRustBuffer<ConversationInitBundle> {
    override fun read(buf: Buffer): ConversationInitBundle {
        return ConversationInitBundle(
            FfiConverterSequenceUByte.read(buf),
            FfiConverterSequenceUByte.read(buf),
            FfiConverterTypePublicGroupStateBundle.read(buf),
        )
    }

    override fun allocationSize(value: ConversationInitBundle) = (
            FfiConverterSequenceUByte.allocationSize(value.`conversationId`) +
            FfiConverterSequenceUByte.allocationSize(value.`commit`) +
            FfiConverterTypePublicGroupStateBundle.allocationSize(value.`publicGroupState`)
    )

    override fun write(value: ConversationInitBundle, buf: Buffer) {
            FfiConverterSequenceUByte.write(value.`conversationId`, buf)
            FfiConverterSequenceUByte.write(value.`commit`, buf)
            FfiConverterTypePublicGroupStateBundle.write(value.`publicGroupState`, buf)
    }
}