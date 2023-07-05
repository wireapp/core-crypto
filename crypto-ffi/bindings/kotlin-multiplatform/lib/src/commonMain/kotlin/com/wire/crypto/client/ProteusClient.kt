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

typealias SessionId = String

data class PreKey(
    val id: UShort,
    val data: ByteArray
)

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

    suspend fun encryptBatched(message: ByteArray, sessionIds: List<SessionId>): Map<SessionId, ByteArray>

    suspend fun encryptWithPreKey(
        message: ByteArray,
        preKey: PreKey,
        sessionId: SessionId
    ): ByteArray
}
