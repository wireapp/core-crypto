package com.wire.crypto.client

import externals.CoreCrypto
import kotlinx.coroutines.await

@Suppress("TooManyFuctions")
class ProteusClientImpl(private val coreCrypto: CoreCrypto): ProteusClient {

    override suspend fun getIdentity(): ByteArray {
        return ByteArray(0)
    }

    override suspend fun getLocalFingerprint(): ByteArray =
        wrapException { coreCrypto.proteusFingerprint().await().encodeToByteArray() }

    override suspend fun getRemoteFingerprint(sessionId: SessionId): ByteArray =
        wrapException { coreCrypto.proteusFingerprintRemote(sessionId).await().encodeToByteArray() }

    override suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey> =
        wrapException {
            from.until(from + count).map {
                toPreKey(it.toUShort(), coreCrypto.proteusNewPrekey(it).await().toByteArray())
            } as ArrayList<PreKey>
        }

    override suspend fun newLastPreKey(): PreKey =
        wrapException { toPreKey(CoreCrypto.proteusLastResortPrekeyId().toInt().toUShort(), coreCrypto.proteusLastResortPrekey().await().toByteArray()) }

    override suspend fun doesSessionExist(sessionId: SessionId): Boolean =
        wrapException { coreCrypto.proteusSessionExists(sessionId).await() }

    override suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId) =
        wrapException { coreCrypto.proteusSessionFromPrekey(sessionId, preKeyCrypto.data.toUint8Array()).await() }

    override suspend fun deleteSession(sessionId: SessionId) =
        wrapException { coreCrypto.proteusSessionDelete(sessionId).await() }

    override suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        val sessionExists = doesSessionExist(sessionId)

        return wrapException {
            if (sessionExists) {
                coreCrypto.proteusDecrypt(sessionId, message.toUint8Array()).await().toByteArray()
            } else  {
                coreCrypto.proteusSessionFromMessage(sessionId, message.toUint8Array()).await().toByteArray()
            }
        }
    }

    override suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray =
        wrapException {
            val encryptedMessage = coreCrypto.proteusEncrypt(sessionId, message.toUint8Array()).await().toByteArray()
            coreCrypto.proteusSessionSave(sessionId)
            return encryptedMessage
        }

    override suspend fun encryptBatched(message: ByteArray, sessionIds: List<SessionId>): Map<SessionId, ByteArray> {
//        wrapException {
        val result = mutableMapOf<SessionId, ByteArray>()
        coreCrypto.proteusEncryptBatched(sessionIds.map { it }.toTypedArray() as Array<String>,
            message.toUint8Array()
        ).await().forEach({ message, sessionId, _ ->
            result[sessionId] = message.toByteArray()
        })
        return result
//        }
    }

    override suspend fun encryptWithPreKey(message: ByteArray, preKey: PreKey, sessionId: SessionId): ByteArray =
        wrapException {
            coreCrypto.proteusSessionFromPrekey(sessionId, preKey.data.toUint8Array()).await()
            val encryptedMessage =
                coreCrypto.proteusEncrypt(sessionId, message.toUint8Array()).await().toByteArray()
            coreCrypto.proteusSessionSave(sessionId)
            return encryptedMessage
        }

    @Suppress("TooGenericExceptionCaught")
    private suspend inline fun <T> wrapException(b: () -> T): T {
        try {
            return b()
        } catch (e: Throwable) {
            throw ProteusException(e.message, ProteusException.fromProteusCode(coreCrypto.proteusLastErrorCode().await().toInt()), e.cause)
        }
    }

    companion object {
        private fun toPreKey(id: UShort, data: ByteArray): PreKey =
            PreKey(id, data)
    }

}
