package com.wire.crypto.client

import com.wire.crypto.ClientId
import com.wire.crypto.ConversationId
import com.wire.crypto.CoreCrypto
import com.wire.crypto.CoreCryptoCallbacks
import java.io.File

private class Callbacks: CoreCryptoCallbacks {

    override fun authorize(
        conversationId: List<UByte>,
        clientId: List<UByte>): Boolean {
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

@Suppress("TooManyFunctions")
class CoreCryptoCentral constructor(
    private val rootDir: String,
    databaseKey: String
) {
    private val path: String = "$rootDir/$KEYSTORE_NAME"
    private val coreCrypto: CoreCrypto
    init {
        File(rootDir).mkdirs()
        coreCrypto = CoreCrypto.deferredInit(path, databaseKey, null)
        coreCrypto.setCallbacks(Callbacks())
    }

    fun proteusClient(): ProteusClient {
        return ProteusClientImpl(coreCrypto, rootDir)
    }

    fun mlsClient(clientId: String): MLSClient {
        return MLSClientImpl(coreCrypto, clientId)
    }

    companion object {
        const val KEYSTORE_NAME = "keystore"
    }
}

