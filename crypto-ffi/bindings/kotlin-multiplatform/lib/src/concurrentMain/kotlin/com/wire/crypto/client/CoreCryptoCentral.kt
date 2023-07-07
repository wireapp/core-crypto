package com.wire.crypto.client

import com.wire.crypto.*
import com.wire.crypto.ClientId

private class Callbacks: CoreCryptoCallbacks {
    override fun authorize(conversationId: ConversationId, clientId: ClientId): Boolean {
        return true
    }

    override fun userAuthorize(
        conversationId: ConversationId,
        externalClientId: ClientId,
        existingClients: List<ClientId>
    ): Boolean {
        return true
    }

    override fun clientIsExistingGroupUser(
        conversationId: ConversationId,
        clientId: ClientId,
        existingClients: List<ClientId>,
        parentConversationClients: List<ClientId>?
    ): Boolean {
        return true
    }
}

actual class CoreCryptoCentral constructor(private val rootDir: String, databaseKey: String) {

    private val path = "$rootDir/$KEYSTORE_NAME"
    private val coreCrypto: CoreCrypto

    init {
        coreCrypto = CoreCrypto.deferredInit(path, databaseKey, DEFAULT_CIPHERSUITES)
        coreCrypto.setCallbacks(Callbacks())
    }

    actual suspend fun proteusClient(): ProteusClient {
        return ProteusClientImpl(coreCrypto, rootDir)
    }

    actual suspend fun mlsClient(clientId: String): MLSClient {
        coreCrypto.mlsInit(clientId.toUByteList(), DEFAULT_CIPHERSUITES)
        return MLSClientImpl(coreCrypto)
    }

    actual companion object {
        const val KEYSTORE_NAME = "keystore"
        fun CiphersuiteName.lower() = (ordinal + 1).toUShort()
        actual val DEFAULT_CIPHERSUITE = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519.lower()
        val DEFAULT_CIPHERSUITES = listOf(DEFAULT_CIPHERSUITE)
    }
}
