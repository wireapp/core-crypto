package com.wire.crypto



fun `version`(): String {
    return FfiConverterString.lift(
    rustCall() { _status ->
    UniFFILib.CoreCrypto_3d4a_version( _status)
})
}

