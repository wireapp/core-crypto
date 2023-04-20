package com.wire.crypto


import okio.Buffer

data class CustomConfiguration (
    var `keyRotationSpan`: kotlin.time.Duration?, 
    var `wirePolicy`: MlsWirePolicy?
) {
    
}

object FfiConverterTypeCustomConfiguration: FfiConverterRustBuffer<CustomConfiguration> {
    override fun read(buf: Buffer): CustomConfiguration {
        return CustomConfiguration(
            FfiConverterOptionalDuration.read(buf),
            FfiConverterOptionalTypeMlsWirePolicy.read(buf),
        )
    }

    override fun allocationSize(value: CustomConfiguration) = (
            FfiConverterOptionalDuration.allocationSize(value.`keyRotationSpan`) +
            FfiConverterOptionalTypeMlsWirePolicy.allocationSize(value.`wirePolicy`)
    )

    override fun write(value: CustomConfiguration, buf: Buffer) {
            FfiConverterOptionalDuration.write(value.`keyRotationSpan`, buf)
            FfiConverterOptionalTypeMlsWirePolicy.write(value.`wirePolicy`, buf)
    }
}