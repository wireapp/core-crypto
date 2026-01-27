@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import testutils.genClientId
import testutils.genDatabaseKey
import java.nio.file.Files
import kotlin.test.*

typealias SessionId = String

/**
 * Creates a number of prekeys starting from the `from` index
 *
 * @param from - starting index
 * @param count - number of prekeys to generate
 * @return: A CBOR-serialized version of the PreKeyBundle corresponding to the newly generated and stored PreKey
 */
suspend fun CoreCryptoContext.proteusNewPreKeys(from: Int, count: Int): ArrayList<ByteArray> {
    return from.until(from + count).map {
        proteusNewPrekey(it.toUShort())
    } as ArrayList<ByteArray>
}

/** Create a session and encrypt a message.
 *
 * @param message the message
 * @param preKey the prekey
 * @param sessionId the session ID to be used
 * @return The CBOR-serialized encrypted message
 */
suspend fun CoreCryptoContext.proteusEncryptWithPreKey(
    message: ByteArray,
    preKey: ByteArray,
    sessionId: SessionId,
): ByteArray {
    proteusSessionFromPrekey(sessionId, preKey)
    val encryptedMessage = proteusEncrypt(sessionId, message)
    proteusSessionSave(sessionId)
    return encryptedMessage
}

internal class ProteusClientTest {
    companion object {
        private val alice = genClientId()
        private val bob = genClientId()
        private const val ALICE_SESSION_ID = "alice1_session1"
        private const val BOB_SESSION_ID = "bob1_session1"
    }

    private fun newProteusClient(clientId: ClientId): CoreCrypto = runBlocking {
        val root = Files.createTempDirectory("mls").toFile()
        val path = root.resolve("keystore-$clientId")
        val key = genDatabaseKey()
        val db = openDatabase(path.absolutePath, key)
        val cc = CoreCrypto(db)
        cc.transaction { it.proteusInit() }
        cc
    }

    @Test
    fun givenProteusClient_whenCallingNewLastKey_thenItReturnsALastPreKey() = runTest {
        val prekeyId = CoreCrypto.proteusLastResortPrekeyId()
        assertEquals(65535u, prekeyId)
    }

    @Test
    fun givenProteusClient_whenCallingNewPreKeys_thenItReturnsAListOfPreKeys() = runTest {
        val aliceClient = newProteusClient(alice)
        val preKeyList = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10) }
        assertEquals(preKeyList.size, 10)
    }

    @Test
    fun givenIncomingPreKeyMessage_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val message = "Hi Alice!"
        val aliceKey = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10).first() }
        val encryptedMessage = bobClient.transaction {
            it.proteusEncryptWithPreKey(message.encodeToByteArray(), aliceKey, ALICE_SESSION_ID)
        }
        val decryptedMessage = aliceClient.transaction { ctx -> ctx.proteusDecryptSafe(BOB_SESSION_ID, encryptedMessage) }
        assertEquals(message, decryptedMessage.decodeToString())
    }

    @Test
    fun givenSessionAlreadyExists_whenCallingDecrypt_thenMessageIsDecrypted() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        val encryptedMessage1 = bobClient.transaction {
            it.proteusEncryptWithPreKey(message1.encodeToByteArray(), aliceKey, ALICE_SESSION_ID)
        }
        aliceClient.transaction { ctx -> ctx.proteusDecryptSafe(BOB_SESSION_ID, encryptedMessage1) }

        val message2 = "Hi again Alice!"
        val encryptedMessage2 = bobClient.transaction { ctx -> ctx.proteusEncrypt(ALICE_SESSION_ID, message2.encodeToByteArray()) }
        val decryptedMessage2 = aliceClient.transaction { ctx ->
            val msg = ctx.proteusDecryptSafe(BOB_SESSION_ID, encryptedMessage2)
            ctx.proteusSessionSave(BOB_SESSION_ID)
            msg
        }

        assertEquals(message2, decryptedMessage2.decodeToString())
    }

    @Test
    fun givenReceivingSameMessageTwice_whenCallingDecrypt_thenDuplicateMessageError() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        val encryptedMessage1 = bobClient.transaction {
            it.proteusEncryptWithPreKey(message1.encodeToByteArray(), aliceKey, ALICE_SESSION_ID)
        }
        aliceClient.transaction { ctx -> ctx.proteusDecryptSafe(BOB_SESSION_ID, encryptedMessage1) }

        val exception = assertFailsWith<CoreCryptoException.Proteus> {
            aliceClient.transaction { ctx -> ctx.proteusDecryptSafe(BOB_SESSION_ID, encryptedMessage1) }
        }
        assertIs<ProteusException.DuplicateMessage>(exception.exception)
    }

    @Test
    fun givenMissingSession_whenCallingEncryptBatched_thenMissingSessionAreIgnored() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)
        val aliceKey = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10).first() }
        val message1 = "Hi Alice!"
        bobClient.transaction { ctx -> ctx.proteusSessionFromPrekey(ALICE_SESSION_ID, aliceKey) }

        val missingAliceSessionId = "missing_session"
        val encryptedMessages =
            bobClient.transaction {
                it.proteusEncryptBatched(listOf(ALICE_SESSION_ID, missingAliceSessionId), message1.encodeToByteArray())
            }

        assertEquals(1, encryptedMessages.size)
        assertTrue(encryptedMessages.containsKey(ALICE_SESSION_ID))
    }

    @Test
    fun givenNoSessionExists_whenCallingCreateSession_thenSessionIsCreated() = runTest {
        val aliceClient = newProteusClient(alice)
        val bobClient = newProteusClient(bob)

        val aliceKey = aliceClient.transaction { ctx -> ctx.proteusNewPreKeys(0, 10).first() }
        bobClient.transaction { ctx -> ctx.proteusSessionFromPrekey(ALICE_SESSION_ID, aliceKey) }
        assertNotNull(bobClient.transaction { ctx -> ctx.proteusEncrypt(ALICE_SESSION_ID, "Hello World".encodeToByteArray()) })
    }

    @Test
    fun givenNoSessionExists_whenGettingRemoteFingerprint_thenReturnSessionNotFound() = runTest {
        val aliceClient = newProteusClient(alice)

        assertFailsWith<CoreCryptoException.Proteus> {
            aliceClient.transaction { ctx ->
                ctx.proteusFingerprintRemote(
                    ALICE_SESSION_ID
                )
            }
        }.also { ctx -> ctx.exception is ProteusException.SessionNotFound }
    }
}
