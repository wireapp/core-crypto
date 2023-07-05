package com.wire.crypto.client

actual open class BaseCoreCryptoCentralTest {
    actual suspend fun createCoreCryptoCentral(id: String): CoreCryptoCentral {
        val coreCrypto = CoreCryptoCentral()
        coreCrypto.open(id, "secret")
        return coreCrypto
    }

}
