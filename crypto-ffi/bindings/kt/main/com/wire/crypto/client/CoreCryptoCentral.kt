package com.wire.crypto.client

import com.wire.crypto.*
import com.wire.crypto.ClientId
import java.io.File

typealias EnrollmentHandle = ByteArray

private class Callbacks : CoreCryptoCallbacks {

    override fun authorize(conversationId: List<UByte>, clientId: List<UByte>): Boolean = true

    override fun userAuthorize(
        conversationId: ConversationId,
        externalClientId: ClientId,
        existingClients: List<ClientId>
    ): Boolean = true

    override fun clientIsExistingGroupUser(
        conversationId: ConversationId,
        clientId: ClientId,
        existingClients: List<ClientId>,
        parentConversationClients: List<ClientId>?
    ): Boolean = true
}

@Suppress("TooManyFunctions")
class CoreCryptoCentral(private val rootDir: String, databaseKey: String) {

    private val path: String = "$rootDir/$KEYSTORE_NAME"
    private val cc: CoreCrypto

    init {
        File(rootDir).mkdirs()
        cc = CoreCrypto.deferredInit(path, databaseKey, DEFAULT_CIPHERSUITES)
        cc.setCallbacks(Callbacks())
    }

    fun proteusClient(): ProteusClient = ProteusClientImpl(cc, rootDir)

    fun mlsClient(clientId: String): MLSClient = MLSClientImpl(cc).apply { mlsInit(clientId) }

    fun e2eiNewEnrollment(
        clientId: String,
        displayName: String,
        handle: String,
        expiryDays: UInt,
        ciphersuite: Ciphersuite,
    ): E2EIClient {
        return E2EIClientImpl(cc.e2eiNewEnrollment(clientId, displayName, handle, expiryDays, ciphersuite))
    }

    fun e2eiMlsClient(enrollment: E2EIClient, certificateChain: String): MLSClient {
        cc.e2eiMlsInit(enrollment.delegate, certificateChain)
        return MLSClientImpl(cc)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    fun e2eiEnrollmentStash(enrollment: E2EIClient): EnrollmentHandle {
        return cc.e2eiEnrollmentStash(enrollment.delegate).toUByteArray().asByteArray()
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    fun e2eiEnrollmentStashPop(handle: EnrollmentHandle): E2EIClient {
        return E2EIClientImpl(cc.e2eiEnrollmentStashPop(handle.asUByteArray().asList()))
    }

    companion object {
        const val KEYSTORE_NAME = "keystore"
        fun CiphersuiteName.lower() = (ordinal + 1).toUShort()
        val DEFAULT_CIPHERSUITE = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519.lower()
        val DEFAULT_CIPHERSUITES = listOf(DEFAULT_CIPHERSUITE)
    }
}

