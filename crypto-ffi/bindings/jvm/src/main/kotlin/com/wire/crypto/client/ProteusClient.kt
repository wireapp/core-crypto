/*
 * Wire
 * Copyright (C) 2023 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 */

package com.wire.crypto.client

import com.wire.crypto.CoreCrypto
import com.wire.crypto.CoreCryptoException
import java.io.File

typealias SessionId = String

data class PreKey(val id: UShort, val data: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PreKey

        if (id != other.id) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}

interface ProteusClient {

    suspend fun getIdentity(): ByteArray

    suspend fun getLocalFingerprint(): ByteArray

    suspend fun getRemoteFingerprint(sessionId: SessionId): ByteArray

    suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey>

    suspend fun newLastPreKey(): PreKey

    suspend fun doesSessionExist(sessionId: SessionId): Boolean

    suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId)

    suspend fun deleteSession(sessionId: SessionId)

    suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray

    suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray

    suspend fun encryptBatched(
        message: ByteArray,
        sessionIds: List<SessionId>,
    ): Map<SessionId, ByteArray>

    suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId,
    ): ByteArray
}

@Suppress("TooManyFunctions")
class ProteusClientImpl private constructor(private val coreCrypto: CoreCrypto) : ProteusClient {
    override suspend fun getIdentity(): ByteArray {
        return ByteArray(0)
    }

    override suspend fun getLocalFingerprint(): ByteArray {
        return wrapException { coreCrypto.proteusFingerprint().toByteArray() }
    }

    override suspend fun getRemoteFingerprint(sessionId: SessionId): ByteArray {
        return wrapException { coreCrypto.proteusFingerprintRemote(sessionId).toByteArray() }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey> {
        return wrapException {
            from.until(from + count).map {
                toPreKey(it.toUShort(), coreCrypto.proteusNewPrekey(it.toUShort()))
            } as ArrayList<PreKey>
        }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun newLastPreKey(): PreKey {
        return wrapException {
            toPreKey(coreCrypto.proteusLastResortPrekeyId(), coreCrypto.proteusLastResortPrekey())
        }
    }

    override suspend fun doesSessionExist(sessionId: SessionId): Boolean {
        return wrapException { coreCrypto.proteusSessionExists(sessionId) }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId) {
        wrapException { coreCrypto.proteusSessionFromPrekey(sessionId, preKeyCrypto.data) }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun deleteSession(sessionId: SessionId) {
        wrapException { coreCrypto.proteusSessionDelete(sessionId) }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        val sessionExists = doesSessionExist(sessionId)

        return wrapException {
            if (sessionExists) {
                val decryptedMessage = coreCrypto.proteusDecrypt(sessionId, message)
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            } else {
                val decryptedMessage = coreCrypto.proteusSessionFromMessage(sessionId, message)
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            }
        }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        return wrapException {
            val encryptedMessage = coreCrypto.proteusEncrypt(sessionId, message)
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun encryptBatched(
        message: ByteArray,
        sessionIds: List<SessionId>,
    ): Map<SessionId, ByteArray> {
        return wrapException {
                coreCrypto.proteusEncryptBatched(sessionIds.map { it }, message).mapNotNull { entry
                    ->
                    entry.key to entry.value
                }
            }
            .toMap()
    }

    @Deprecated(
        "Use this method from the CoreCryptoContext object created from a CoreCryptoCentral.transaction call"
    )
    override suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId,
    ): ByteArray {
        return wrapException {
            coreCrypto.proteusSessionFromPrekey(sessionId, preKey.data)
            val encryptedMessage = coreCrypto.proteusEncrypt(sessionId, message)
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun <T> wrapException(b: suspend () -> T): T {
        try {
            return b()
        } catch (e: CoreCryptoException) {
            throw ProteusException.fromCoreCryptoException(coreCrypto.proteusLastErrorCode(), e)
        } catch (e: Exception) {
            throw ProteusException(e.message, ProteusException.Code.UNKNOWN_ERROR, e.cause)
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    companion object {
        private fun toUByteList(value: ByteArray): List<UByte> = value.asUByteArray().asList()

        private fun toByteArray(value: List<UByte>) = value.toUByteArray().asByteArray()

        private fun toPreKey(id: UShort, data: ByteArray): PreKey = PreKey(id, data)

        public fun needsMigration(rootDir: File): Boolean {
            return cryptoBoxFilesExists(rootDir)
        }

        private fun cryptoBoxFilesExists(rootDir: File): Boolean =
            CRYPTO_BOX_FILES.any { rootDir.resolve(it).exists() }

        private val CRYPTO_BOX_FILES = listOf("identities", "prekeys", "sessions", "version")

        private fun deleteCryptoBoxFiles(rootDir: String): Boolean =
            CRYPTO_BOX_FILES.fold(true) { acc, file ->
                acc && File(rootDir).resolve(file).deleteRecursively()
            }

        private suspend fun migrateFromCryptoBoxIfNecessary(
            coreCrypto: CoreCrypto,
            rootDir: String,
        ) {
            if (cryptoBoxFilesExists(File(rootDir))) {
                coreCrypto.proteusCryptoboxMigrate(rootDir)
                deleteCryptoBoxFiles(rootDir)
            }
        }

        suspend operator fun invoke(coreCrypto: CoreCrypto, rootDir: String): ProteusClientImpl {
            try {
                migrateFromCryptoBoxIfNecessary(coreCrypto, rootDir)
                coreCrypto.proteusInit()
                return ProteusClientImpl(coreCrypto)
            } catch (e: CoreCryptoException) {
                throw ProteusException.fromCoreCryptoException(coreCrypto.proteusLastErrorCode(), e)
            } catch (e: Exception) {
                throw ProteusException(e.message, ProteusException.Code.UNKNOWN_ERROR, e.cause)
            }
        }
    }
}
