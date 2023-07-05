package com.wire.crypto.client

import com.wire.crypto.CoreCrypto
import com.wire.crypto.CryptoException

@Suppress("TooManyFunctions")
class ProteusClientImpl constructor(
    private val coreCrypto: CoreCrypto,
    val rootDir: String
) : ProteusClient {

    init {
        wrapException {
            migrateFromCryptoBoxIfNecessary(coreCrypto)
            coreCrypto.proteusInit()
        }
    }

    private fun deleteCryptoBoxFiles(): Boolean =
        CRYPTO_BOX_FILES.fold(true) { acc, file ->
            acc && FileHelper.deleteFilesAtPath("$rootDir/$file")
        }

    private fun migrateFromCryptoBoxIfNecessary(coreCrypto: CoreCrypto) {
        if (cryptoBoxFilesExists(rootDir)) {
            migrateFromCryptoBox(coreCrypto)
        }
    }

    private fun migrateFromCryptoBox(coreCrypto: CoreCrypto) {
        coreCrypto.proteusCryptoboxMigrate(rootDir)
        deleteCryptoBoxFiles()
    }

    override suspend fun getIdentity(): ByteArray {
        return ByteArray(0)
    }

    override suspend fun getLocalFingerprint(): ByteArray {
        return wrapException { coreCrypto.proteusFingerprint().encodeToByteArray() }
    }

    override suspend fun getRemoteFingerprint(sessionId: SessionId): ByteArray {
        return wrapException { coreCrypto.proteusFingerprintRemote(sessionId).encodeToByteArray() }
    }

    override suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey> {
        return wrapException {
            from.until(from + count).map {
                toPreKey(it.toUShort(), coreCrypto.proteusNewPrekey(it.toUShort()).toByteArray())
            } as ArrayList<PreKey>
        }
    }

    override suspend fun newLastPreKey(): PreKey {
        return wrapException { toPreKey(coreCrypto.proteusLastResortPrekeyId(), coreCrypto.proteusLastResortPrekey().toByteArray()) }
    }

    override suspend fun doesSessionExist(sessionId: SessionId): Boolean {
        return wrapException {
            coreCrypto.proteusSessionExists(sessionId)
        }
    }

    override suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId) {
        wrapException { coreCrypto.proteusSessionFromPrekey(sessionId, preKeyCrypto.data.toUByteList()) }
    }

    override suspend fun deleteSession(sessionId: SessionId) {
        wrapException {
            coreCrypto.proteusSessionDelete(sessionId)
        }
    }

    override suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        val sessionExists = doesSessionExist(sessionId)

        return wrapException {
            if (sessionExists) {
                val decryptedMessage = coreCrypto.proteusDecrypt(sessionId, message.toUByteList()).toByteArray()
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            } else {
                val decryptedMessage = coreCrypto.proteusSessionFromMessage(sessionId, message.toUByteList()).toByteArray()
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            }
        }
    }

    override suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        return wrapException {
            val encryptedMessage = coreCrypto.proteusEncrypt(sessionId, message.toUByteList()).toByteArray()
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    override suspend fun encryptBatched(message: ByteArray, sessionIds: List<SessionId>): Map<SessionId, ByteArray> {
        return wrapException {
            coreCrypto.proteusEncryptBatched(sessionIds.map { it }, message.toUByteList()).mapNotNull { entry ->
                entry.key to entry.value.toByteArray()
            }
        }.toMap()
    }

    override suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId
    ): ByteArray {
        return wrapException {
            coreCrypto.proteusSessionFromPrekey(sessionId, preKey.data.toUByteList())
            val encryptedMessage = coreCrypto.proteusEncrypt(sessionId, message.toUByteList()).toByteArray()
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun <T> wrapException(b: () -> T): T {
        try {
            return b()
        } catch (e: CryptoException) {
            throw ProteusException(e.message, ProteusException.fromProteusCode(coreCrypto.proteusLastErrorCode().toInt()), e.cause)
        } catch (e: Exception) {
            throw ProteusException(e.message, ProteusException.Code.UNKNOWN_ERROR, e.cause)
        }
    }

    companion object {
        private fun toPreKey(id: UShort, data: ByteArray): PreKey =
            PreKey(id, data)

        public fun needsMigration(rootDir: String): Boolean {
            return cryptoBoxFilesExists(rootDir)
        }

        private fun cryptoBoxFilesExists(rootDir: String): Boolean =
            CRYPTO_BOX_FILES.any {
                FileHelper.fileExistsAtPath("$rootDir/$it")
            }

        private val CRYPTO_BOX_FILES = listOf("identities", "prekeys", "sessions", "version")
    }
}
