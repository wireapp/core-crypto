package com.wire.crypto.client

import com.wire.crypto.client.Ciphersuite
import externals.*
import org.khronos.webgl.Uint8Array
import kotlin.js.Promise
import kotlinx.coroutines.await

private class Callbacks: CoreCryptoCallbacks {
    override var authorize: (conversationId: Uint8Array, clientId: Uint8Array) -> Promise<Boolean>
        get() = { _, _ -> Promise.resolve(true) }
        set(value) {}
    override var userAuthorize: (conversationId: Uint8Array, externalClientId: Uint8Array, existingClients: Array<Uint8Array>) -> Promise<Boolean>
        get() = { _, _, _ -> Promise.resolve(true) }
        set(value) {}
    override var clientIsExistingGroupUser: (conversationId: Uint8Array, clientId: Uint8Array, existingClients: Array<Uint8Array>, parent_conversation_clients: Array<Uint8Array>) -> Promise<Boolean>
        get() = { _, _, _, _ -> Promise.resolve(true) }
        set(value) {}

}

private class DeferredParams(
    override var databaseName: String,
    override var key: String,
    override var ciphersuites: Array<externals.Ciphersuite>
) : CoreCryptoDeferredParams

actual class CoreCryptoCentral {

    private lateinit var coreCrypto: CoreCrypto

    suspend fun open(databaseName: String, databaseKey: String) {
        coreCrypto = CoreCrypto.deferredInit(
            DeferredParams(
                databaseName,
                databaseKey,
                DEFAULT_CIPHERSUITES.toTypedArray()
            )
        ).await()
        coreCrypto.registerCallbacks(Callbacks()).await()
    }

    actual suspend fun proteusClient(): ProteusClient {
        coreCrypto.proteusInit().await()
        return ProteusClientImpl(coreCrypto)
    }

    actual suspend fun mlsClient(clientId: String): MLSClient {
        coreCrypto.mlsInit(clientId.encodeToByteArray().toUint8Array(), DEFAULT_CIPHERSUITES.toTypedArray()).await()
        return MLSClientImpl(coreCrypto)
    }

    actual companion object {
        actual val DEFAULT_CIPHERSUITE: Ciphersuite = 1.toUShort()
        val DEFAULT_ENUM_CIPHERSUITE = externals.Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        val DEFAULT_CIPHERSUITES = listOf(DEFAULT_ENUM_CIPHERSUITE)
    }
}
