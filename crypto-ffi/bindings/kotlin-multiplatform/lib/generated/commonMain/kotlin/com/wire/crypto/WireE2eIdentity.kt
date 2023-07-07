package com.wire.crypto


import okio.Buffer

interface WireE2eIdentityInterface {
    
    @Throws(E2eIdentityException::class)
    fun `directoryResponse`(`directory`: List<UByte>): AcmeDirectory
    
    @Throws(E2eIdentityException::class)
    fun `newAccountRequest`(`previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `newAccountResponse`(`account`: List<UByte>)
    
    @Throws(E2eIdentityException::class)
    fun `newOrderRequest`(`previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `newOrderResponse`(`order`: List<UByte>): NewAcmeOrder
    
    @Throws(E2eIdentityException::class)
    fun `newAuthzRequest`(`url`: String, `previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `newAuthzResponse`(`authz`: List<UByte>): NewAcmeAuthz
    
    @Throws(E2eIdentityException::class)
    fun `createDpopToken`(`expirySecs`: UInt, `backendNonce`: String): String
    
    @Throws(E2eIdentityException::class)
    fun `newDpopChallengeRequest`(`accessToken`: String, `previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `newOidcChallengeRequest`(`idToken`: String, `previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `newChallengeResponse`(`challenge`: List<UByte>)
    
    @Throws(E2eIdentityException::class)
    fun `checkOrderRequest`(`orderUrl`: String, `previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `checkOrderResponse`(`order`: List<UByte>): String
    
    @Throws(E2eIdentityException::class)
    fun `finalizeRequest`(`previousNonce`: String): List<UByte>
    
    @Throws(E2eIdentityException::class)
    fun `finalizeResponse`(`finalize`: List<UByte>): String
    
    @Throws(E2eIdentityException::class)
    fun `certificateRequest`(`previousNonce`: String): List<UByte>
    
}

class WireE2eIdentity(
    pointer: Pointer
) : FFIObject(pointer), WireE2eIdentityInterface {

    override protected fun freeRustArcPtr() {
        rustCall() { status ->
            UniFFILib.ffi_CoreCrypto_fbd8_WireE2eIdentity_object_free(this.pointer, status)
        }
    }

    
    @Throws(E2eIdentityException::class)override fun `directoryResponse`(`directory`: List<UByte>): AcmeDirectory =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_directory_response(it, FfiConverterSequenceUByte.lower(`directory`),  _status)
}
        }.let {
            FfiConverterTypeAcmeDirectory.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newAccountRequest`(`previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_account_request(it, FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newAccountResponse`(`account`: List<UByte>) =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_account_response(it, FfiConverterSequenceUByte.lower(`account`),  _status)
}
        }
    
    
    @Throws(E2eIdentityException::class)override fun `newOrderRequest`(`previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_order_request(it, FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newOrderResponse`(`order`: List<UByte>): NewAcmeOrder =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_order_response(it, FfiConverterSequenceUByte.lower(`order`),  _status)
}
        }.let {
            FfiConverterTypeNewAcmeOrder.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newAuthzRequest`(`url`: String, `previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_authz_request(it, FfiConverterString.lower(`url`), FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newAuthzResponse`(`authz`: List<UByte>): NewAcmeAuthz =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_authz_response(it, FfiConverterSequenceUByte.lower(`authz`),  _status)
}
        }.let {
            FfiConverterTypeNewAcmeAuthz.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `createDpopToken`(`expirySecs`: UInt, `backendNonce`: String): String =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_create_dpop_token(it, FfiConverterUInt.lower(`expirySecs`), FfiConverterString.lower(`backendNonce`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newDpopChallengeRequest`(`accessToken`: String, `previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_dpop_challenge_request(it, FfiConverterString.lower(`accessToken`), FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newOidcChallengeRequest`(`idToken`: String, `previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_oidc_challenge_request(it, FfiConverterString.lower(`idToken`), FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `newChallengeResponse`(`challenge`: List<UByte>) =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_new_challenge_response(it, FfiConverterSequenceUByte.lower(`challenge`),  _status)
}
        }
    
    
    @Throws(E2eIdentityException::class)override fun `checkOrderRequest`(`orderUrl`: String, `previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_check_order_request(it, FfiConverterString.lower(`orderUrl`), FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `checkOrderResponse`(`order`: List<UByte>): String =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_check_order_response(it, FfiConverterSequenceUByte.lower(`order`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `finalizeRequest`(`previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_finalize_request(it, FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `finalizeResponse`(`finalize`: List<UByte>): String =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_finalize_response(it, FfiConverterSequenceUByte.lower(`finalize`),  _status)
}
        }.let {
            FfiConverterString.lift(it)
        }
    
    @Throws(E2eIdentityException::class)override fun `certificateRequest`(`previousNonce`: String): List<UByte> =
        callWithPointer {
    rustCallWithError(E2eIdentityException) { _status ->
    UniFFILib.CoreCrypto_fbd8_WireE2eIdentity_certificate_request(it, FfiConverterString.lower(`previousNonce`),  _status)
}
        }.let {
            FfiConverterSequenceUByte.lift(it)
        }
    

    
}

object FfiConverterTypeWireE2eIdentity: FfiConverter<WireE2eIdentity, Pointer> {
    override fun lower(value: WireE2eIdentity): Pointer = value.callWithPointer { it }

    override fun lift(value: Pointer): WireE2eIdentity {
        return WireE2eIdentity(value)
    }

    override fun read(buf: Buffer): WireE2eIdentity {
        return lift(buf.readLong().toPointer())
    }

    override fun allocationSize(value: WireE2eIdentity) = 8

    override fun write(value: WireE2eIdentity, buf: Buffer) {
        buf.writeLong(lower(value).toLong())
    }
}