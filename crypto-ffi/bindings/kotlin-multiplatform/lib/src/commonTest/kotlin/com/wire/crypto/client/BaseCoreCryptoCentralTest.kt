package com.wire.crypto.client

expect open class BaseCoreCryptoCentralTest() {
    suspend fun createCoreCryptoCentral(id: String): CoreCryptoCentral
}
