package com.wire.crypto

import com.wire.crypto.testutils.genDatabaseKey
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
        val key = genDatabaseKey()
        val cc = CoreCrypto(keyStore.absolutePath, key)
        cc.transaction { it.proteusInit() }
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
