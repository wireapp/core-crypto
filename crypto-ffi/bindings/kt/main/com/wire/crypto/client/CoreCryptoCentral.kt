package com.wire.crypto.client

import com.wire.crypto.*
import java.io.File

typealias EnrollmentHandle = ByteArray

private class Callbacks : CoreCryptoCallbacks {

    override fun authorize(conversationId: ByteArray, clientId: List<UByte>): Boolean = true

    override fun userAuthorize(
        conversationId: ByteArray,
        externalClientId: List<UByte>,
        existingClients: List<List<UByte>>
    ): Boolean = true

    override fun clientIsExistingGroupUser(
        conversationId: ByteArray,
        clientId: List<UByte>,
        existingClients: List<List<UByte>>,
        parentConversationClients: List<List<UByte>>?
    ): Boolean = true
}

@Suppress("TooManyFunctions")
class CoreCryptoCentral private constructor(private val cc: CoreCrypto, private val rootDir: String) {
    suspend fun proteusClient(): ProteusClient = ProteusClientImpl(cc, rootDir)

    suspend fun mlsClient(clientId: String): MLSClient = MLSClientImpl(cc).apply { mlsInit(clientId) }

    suspend fun e2eiNewEnrollment(
        clientId: String,
        displayName: String,
        handle: String,
        expiryDays: UInt,
        ciphersuite: Ciphersuite,
    ): E2EIClient {
        return E2EIClientImpl(cc.e2eiNewEnrollment(clientId, displayName, handle, expiryDays, ciphersuite))
    }

    suspend fun e2eiMlsInitOnly(enrollment: E2EIClient, certificateChain: String): MLSClient {
        cc.e2eiMlsInitOnly(enrollment.delegate, certificateChain)
        return MLSClientImpl(cc)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    suspend fun e2eiEnrollmentStash(enrollment: E2EIClient): EnrollmentHandle {
        return cc.e2eiEnrollmentStash(enrollment.delegate).toUByteArray().asByteArray()
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    suspend fun e2eiEnrollmentStashPop(handle: EnrollmentHandle): E2EIClient {
        return E2EIClientImpl(cc.e2eiEnrollmentStashPop(handle.asUByteArray().asList()))
    }

    companion object {
        const val KEYSTORE_NAME = "keystore"
        fun CiphersuiteName.lower() = (ordinal + 1).toUShort()
        val DEFAULT_CIPHERSUITE = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519.lower()
        val DEFAULT_CIPHERSUITES = listOf(DEFAULT_CIPHERSUITE)

        suspend operator fun invoke(rootDir: String, databaseKey: String): CoreCryptoCentral {
            val path: String = "$rootDir/$KEYSTORE_NAME"
            File(rootDir).mkdirs()
            val cc = coreCryptoDeferredInit(path, databaseKey, DEFAULT_CIPHERSUITES)
            cc.setCallbacks(Callbacks())
            return CoreCryptoCentral(cc, rootDir)
        }
    }
}

