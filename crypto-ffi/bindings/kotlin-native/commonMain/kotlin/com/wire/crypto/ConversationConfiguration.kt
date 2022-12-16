package com.wire.crypto


import okio.Buffer

data class ConversationConfiguration (
    var `ciphersuite`: CiphersuiteName?, 
    var `externalSenders`: List<List<UByte>>, 
    var `custom`: CustomConfiguration
) {
    
}

object FfiConverterTypeConversationConfiguration: FfiConverterRustBuffer<ConversationConfiguration> {
    override fun read(buf: Buffer): ConversationConfiguration {
        return ConversationConfiguration(
            FfiConverterOptionalTypeCiphersuiteName.read(buf),
            FfiConverterSequenceSequenceUByte.read(buf),
            FfiConverterTypeCustomConfiguration.read(buf),
        )
    }

    override fun allocationSize(value: ConversationConfiguration) = (
            FfiConverterOptionalTypeCiphersuiteName.allocationSize(value.`ciphersuite`) +
            FfiConverterSequenceSequenceUByte.allocationSize(value.`externalSenders`) +
            FfiConverterTypeCustomConfiguration.allocationSize(value.`custom`)
    )

    override fun write(value: ConversationConfiguration, buf: Buffer) {
            FfiConverterOptionalTypeCiphersuiteName.write(value.`ciphersuite`, buf)
            FfiConverterSequenceSequenceUByte.write(value.`externalSenders`, buf)
            FfiConverterTypeCustomConfiguration.write(value.`custom`, buf)
    }
}