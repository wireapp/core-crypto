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
import com.wire.crypto.CryptoException
import java.io.File

typealias SessionId = String

data class PreKey(
    val id: UShort,
    val data: ByteArray
)

interface ProteusClient {

    fun getIdentity(): ByteArray

    fun getLocalFingerprint(): ByteArray

    suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey>

    suspend fun newLastPreKey(): PreKey

    suspend fun doesSessionExist(sessionId: SessionId): Boolean

    suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId)

    suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray

    suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray

    suspend fun encryptBatched(message: ByteArray, sessionIds: List<SessionId>): Map<SessionId, ByteArray>

    suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId
    ): ByteArray

    suspend fun deleteSession(sessionId: SessionId)
}

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

    private fun cryptoBoxFilesExists(): Boolean =
        CRYPTO_BOX_FILES.any {
            File(rootDir).resolve(it).exists()
        }

    private fun deleteCryptoBoxFiles(): Boolean =
        CRYPTO_BOX_FILES.fold(true) { acc, file ->
            acc && File(rootDir).resolve(file).deleteRecursively()
        }

    private fun migrateFromCryptoBoxIfNecessary(coreCrypto: CoreCrypto) {
        if (cryptoBoxFilesExists(File(rootDir))) {
            migrateFromCryptoBox(coreCrypto)
        }
    }

    private fun migrateFromCryptoBox(coreCrypto: CoreCrypto) {
        coreCrypto.proteusCryptoboxMigrate(rootDir)
        deleteCryptoBoxFiles()
    }

    override fun getIdentity(): ByteArray {
        return ByteArray(0)
    }

    override fun getLocalFingerprint(): ByteArray {
        return wrapException { coreCrypto.proteusFingerprint().toByteArray() }
    }

    override suspend fun newPreKeys(from: Int, count: Int): ArrayList<PreKey> {
        return wrapException {
            from.until(from + count).map {
                toPreKey(it.toUShort(), toByteArray(coreCrypto.proteusNewPrekey(it.toUShort())))
            } as ArrayList<PreKey>
        }
    }

    override suspend fun newLastPreKey(): PreKey {
        return wrapException { toPreKey(coreCrypto.proteusLastResortPrekeyId(), toByteArray(coreCrypto.proteusLastResortPrekey())) }
    }

    override suspend fun doesSessionExist(sessionId: SessionId): Boolean {
        return wrapException {
            coreCrypto.proteusSessionExists(sessionId)
        }
    }

    override suspend fun createSession(preKeyCrypto: PreKey, sessionId: SessionId) {
        wrapException { coreCrypto.proteusSessionFromPrekey(sessionId, toUByteList(preKeyCrypto.data)) }
    }

    override suspend fun decrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        val sessionExists = doesSessionExist(sessionId)

        return wrapException {
            if (sessionExists) {
                val decryptedMessage = toByteArray(coreCrypto.proteusDecrypt(sessionId, toUByteList(message)))
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            } else {
                val decryptedMessage = toByteArray(coreCrypto.proteusSessionFromMessage(sessionId, toUByteList(message)))
                coreCrypto.proteusSessionSave(sessionId)
                decryptedMessage
            }
        }
    }

    override suspend fun encrypt(message: ByteArray, sessionId: SessionId): ByteArray {
        return wrapException {
            val encryptedMessage = toByteArray(coreCrypto.proteusEncrypt(sessionId, toUByteList(message)))
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    override suspend fun encryptBatched(message: ByteArray, sessionIds: List<SessionId>): Map<SessionId, ByteArray> {
        return wrapException {
            coreCrypto.proteusEncryptBatched(sessionIds.map { it }, toUByteList((message))).mapNotNull { entry ->
                    entry.key to toByteArray(entry.value)
                }
            }.toMap()
        }

    override suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId
    ): ByteArray {
        return wrapException {
            coreCrypto.proteusSessionFromPrekey(sessionId, toUByteList(preKey.data))
            val encryptedMessage = toByteArray(coreCrypto.proteusEncrypt(sessionId, toUByteList(message)))
            coreCrypto.proteusSessionSave(sessionId)
            encryptedMessage
        }
    }

    override suspend fun deleteSession(sessionId: SessionId) {
        wrapException {
            coreCrypto.proteusSessionDelete(sessionId)
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

    @OptIn(ExperimentalUnsignedTypes::class)
    private companion object {
        fun toUByteList(value: ByteArray): List<UByte> = value.asUByteArray().asList()
        fun toByteArray(value: List<UByte>) = value.toUByteArray().asByteArray()
        fun toPreKey(id: UShort, data: ByteArray): PreKey =
            PreKey(id, data)

        fun needsMigration(rootDir: File): Boolean {
            return cryptoBoxFilesExists(rootDir)
        }

        private fun cryptoBoxFilesExists(rootDir: File): Boolean =
            CRYPTO_BOX_FILES.any {
                rootDir.resolve(it).exists()
            }

        val CRYPTO_BOX_FILES = listOf("identities", "prekeys", "sessions", "version")
    }
}