package com.wire.crypto



fun `version`(): String {
    return FfiConverterString.lift(
    rustCall() { _status ->
    UniFFILib.CoreCrypto_fbd8_version( _status)
})
}

