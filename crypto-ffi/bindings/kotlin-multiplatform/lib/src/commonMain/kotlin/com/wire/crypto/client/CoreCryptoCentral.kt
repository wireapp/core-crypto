package com.wire.crypto.client

@Suppress("TooManyFunctions")
expect class CoreCryptoCentral {
    suspend fun proteusClient(): ProteusClient
    suspend fun mlsClient(clientId: String): MLSClient

    companion object {
        val DEFAULT_CIPHERSUITE: Ciphersuite
    }
}

