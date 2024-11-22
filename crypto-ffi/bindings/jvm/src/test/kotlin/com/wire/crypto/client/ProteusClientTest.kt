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

import com.wire.crypto.client.*
import java.nio.file.Files
import kotlin.test.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest

@OptIn(ExperimentalCoroutinesApi::class)
internal class ProteusClientTest {

    companion object {
        private val alice = "alice1".toClientId()
        private val bob = "bob1".toClientId()
        private const val aliceSessionId = "alice1_session1"
        private const val bobSessionId = "bob1_session1"
    }

    private suspend fun newProteusClient(clientId: ClientId): ProteusClient = runBlocking {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$clientId")
        CoreCryptoCentral(keyStore.absolutePath, "secret").proteusClient()
    }

    @Test
    fun givenProteusClient_whenCallingNewLastKey_thenItReturnsALastPreKey() = runTest {
        val aliceClient = newProteusClient(alice)
        val lastPreKey = aliceClient.newLastPreKey()
        assertEquals(65535u, lastPreKey.id)
    }

    @Test
    fun givenProteusClient_whenCallingNewPreKeys_thenItReturnsAListOfPreKeys() = runTest {
        val aliceClient = newProteusClient(alice)
        val preKeyList = aliceClient.newPreKeys(0, 10)
        assertEquals(preKeyList.size, 10)
    }

    @Test
    fun givenIncomingPreKeyMessage_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val message = "Hi Alice!"
        val aliceKey = aliceClient.newPreKeys(0, 10).first()
        val encryptedMessage =
            bobClient.encryptWithPreKey(message.encodeToByteArray(), aliceKey, aliceSessionId)
        val decryptedMessage = aliceClient.decrypt(encryptedMessage, bobSessionId)
        assertEquals(message, decryptedMessage.decodeToString())
    }

    @Test
    fun givenSessionAlreadyExists_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.newPreKeys(0, 10).first()
        val message1 = "Hi Alice!"
        val encryptedMessage1 =
            bobClient.encryptWithPreKey(message1.encodeToByteArray(), aliceKey, aliceSessionId)
        aliceClient.decrypt(encryptedMessage1, bobSessionId)

        val message2 = "Hi again Alice!"
        val encryptedMessage2 = bobClient.encrypt(message2.encodeToByteArray(), aliceSessionId)
        val decryptedMessage2 = aliceClient.decrypt(encryptedMessage2, bobSessionId)

        assertEquals(message2, decryptedMessage2.decodeToString())
    }

    @Test
    fun givenReceivingSameMessageTwice_whenCallingDecrypt_thenDuplicateMessageError() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.newPreKeys(0, 10).first()
        val message1 = "Hi Alice!"
        val encryptedMessage1 =
            bobClient.encryptWithPreKey(message1.encodeToByteArray(), aliceKey, aliceSessionId)
        aliceClient.decrypt(encryptedMessage1, bobSessionId)

        val exception: ProteusException = assertFailsWith {
            aliceClient.decrypt(encryptedMessage1, bobSessionId)
        }
        assertEquals(ProteusException.Code.DUPLICATE_MESSAGE, exception.code)
    }

    @Test
    fun givenMissingSession_whenCallingEncryptBatched_thenMissingSessionAreIgnored() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.newPreKeys(0, 10).first()
        val message1 = "Hi Alice!"
        bobClient.createSession(aliceKey, aliceSessionId)

        val missingAliceSessionId = "missing_session"
        val encryptedMessages =
            bobClient.encryptBatched(
                message1.encodeToByteArray(),
                listOf(aliceSessionId, missingAliceSessionId),
            )

        assertEquals(1, encryptedMessages.size)
        assertTrue(encryptedMessages.containsKey(aliceSessionId))
    }

    @Test
    fun givenNoSessionExists_whenCallingCreateSession_thenSessionIsCreated() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val aliceKey = aliceClient.newPreKeys(0, 10).first()
        bobClient.createSession(aliceKey, aliceSessionId)
        assertNotNull(bobClient.encrypt("Hello World".encodeToByteArray(), aliceSessionId))
    }
}
