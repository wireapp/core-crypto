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

package com.wire.crypto

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import java.nio.file.Files
import kotlin.test.*

internal class ProteusClientTest {

    companion object {
        private val alice = "alice1".toClientId()
        private val bob = "bob1".toClientId()
        private const val aliceSessionId = "alice1_session1"
        private const val bobSessionId = "bob1_session1"
    }

    private fun newProteusClient(clientId: ClientId): CoreCrypto = runBlocking {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$clientId")
        val cc = CoreCrypto(keyStore.absolutePath, "secret")
        cc.proteusInit()
        cc
    }

    @Test
    fun givenProteusClient_whenCallingNewLastKey_thenItReturnsALastPreKey() = runTest {
        val aliceClient = newProteusClient(alice)
        val lastPreKey = aliceClient.transaction { it.proteusNewLastPreKey() }
        assertEquals(65535u, lastPreKey.id)
    }

    @Test
    fun givenProteusClient_whenCallingNewPreKeys_thenItReturnsAListOfPreKeys() = runTest {
        val aliceClient = newProteusClient(alice)
        val preKeyList = aliceClient.transaction { it.proteusNewPreKeys(0, 10) }
        assertEquals(preKeyList.size, 10)
    }

    @Test
    fun givenIncomingPreKeyMessage_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val message = "Hi Alice!"
        val aliceKey = aliceClient.transaction {  it.proteusNewPreKeys(0, 10).first() }
        val encryptedMessage = bobClient.transaction { it.proteusEncryptWithPreKey(message.encodeToByteArray(), aliceKey, aliceSessionId) }
        val decryptedMessage = aliceClient.transaction { it.proteusDecrypt(encryptedMessage, bobSessionId) }
        assertEquals(message, decryptedMessage.decodeToString())
    }

    @Test
    fun givenSessionAlreadyExists_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { it.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        val encryptedMessage1 = bobClient.transaction { it.proteusEncryptWithPreKey(message1.encodeToByteArray(), aliceKey, aliceSessionId) }
        aliceClient.transaction { it.proteusDecrypt(encryptedMessage1, bobSessionId) }

        val message2 = "Hi again Alice!"
        val encryptedMessage2 = bobClient.transaction { it.proteusEncrypt(message2.encodeToByteArray(), aliceSessionId) }
        val decryptedMessage2 = aliceClient.transaction { it.proteusDecrypt(encryptedMessage2, bobSessionId) }

        assertEquals(message2, decryptedMessage2.decodeToString())
    }

    @Test
    fun givenReceivingSameMessageTwice_whenCallingDecrypt_thenDuplicateMessageError() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { it.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        val encryptedMessage1 = bobClient.transaction { it.proteusEncryptWithPreKey(message1.encodeToByteArray(), aliceKey, aliceSessionId) }
        aliceClient.transaction { it.proteusDecrypt(encryptedMessage1, bobSessionId) }

        val exception: CoreCryptoException.Proteus = assertFailsWith {
            aliceClient.transaction { it.proteusDecrypt(encryptedMessage1, bobSessionId) }
        }
        assertEquals(ProteusException.DuplicateMessage(), exception.exception)
    }

    @Test
    fun givenMissingSession_whenCallingEncryptBatched_thenMissingSessionAreIgnored() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { it.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        bobClient.transaction { it.proteusCreateSession(aliceKey, aliceSessionId) }

        val missingAliceSessionId = "missing_session"
        val encryptedMessages =
            bobClient.transaction { it.proteusEncryptBatched(listOf(aliceSessionId, missingAliceSessionId), message1.encodeToByteArray()) }

        assertEquals(1, encryptedMessages.size)
        assertTrue(encryptedMessages.containsKey(aliceSessionId))
    }

    @Test
    fun givenNoSessionExists_whenCallingCreateSession_thenSessionIsCreated() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val aliceKey = aliceClient.transaction { it.proteusNewPreKeys(0, 10).first() }
        bobClient.transaction { it.proteusCreateSession(aliceKey, aliceSessionId) }
        assertNotNull(bobClient.transaction { it.proteusEncrypt("Hello World".encodeToByteArray(), aliceSessionId) })
    }
}
