package com.wire.crypto.client

import com.wire.crypto.ClientId
import com.wire.crypto.ConversationId
import com.wire.crypto.CoreCrypto
import com.wire.crypto.CoreCryptoCallbacks

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
        coreCrypto = CoreCrypto.deferredInit(path, databaseKey, null)
        coreCrypto.setCallbacks(Callbacks())
    }

    actual suspend fun proteusClient(): ProteusClient {
        return ProteusClientImpl(coreCrypto, rootDir)
    }

    actual suspend fun mlsClient(clientId: String): MLSClient {
        coreCrypto.mlsInit(clientId.toUByteList())
        return MLSClientImpl(coreCrypto)
    }

    companion object {
        const val KEYSTORE_NAME = "keystore"
    }
}
