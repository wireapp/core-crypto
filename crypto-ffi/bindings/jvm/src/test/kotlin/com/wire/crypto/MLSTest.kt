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

import com.wire.crypto.uniffi.CommitBundle
import com.wire.crypto.uniffi.MlsTransportResponse
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import java.nio.file.Files
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds

class MLSTest {

    companion object {
        internal val id = "JfflcPtUivbg+1U3Iyrzsh5D2ui/OGS5Rvf52ipH5KY=".toGroupId()
        internal val aliceId = "alice1"
        internal val aliceId2 = "alice2"
        internal val bobId = "bob"
        internal val carolId = "carol"
        internal lateinit var mockDeliveryService: MockDeliveryService
    }

    @BeforeTest
    fun setup() {
        mockDeliveryService = MockMlsTransportSuccessProvider()
    }

    @Test
    fun set_client_data_persists() = runTest {
        val cc = initCc()

        val data = "my message processing checkpoint".toByteArray()

        cc.transaction { ctx ->
            assertThat(ctx.getData()).isNull()
            ctx.setData(data)
        }

        cc.transaction { ctx -> assertThat(ctx.getData()).isEqualTo(data) }
    }

    @Test
    fun externally_generated_ClientId_should_init_the_MLS_client() = runTest {
        val alice = initCc()
        val handle = alice.transaction { it.mlsGenerateKeypairs() }
        alice.transaction { it.mlsInitWithClientId(aliceId.toClientId(), handle) }
    }

    @Test
    fun interaction_with_invalid_context_throws_error() = runTest {
        val cc = initCc()
        var context: CoreCryptoContext? = null

        cc.transaction { ctx -> context = ctx }

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> {
                context!!.mlsInit(aliceId.toClientId())
            }

        assertIs<MlsException.Other>(expectedException.exception)
    }

    @Test
    fun error_is_propagated_by_transaction() = runTest {
        val cc = initCc()
        val expectedException = RuntimeException("Expected Exception")

        val actualException =
            assertFailsWith<RuntimeException> { cc.transaction<Unit> { throw expectedException } }

        assertEquals(expectedException, actualException)
    }

    @Test
    fun transaction_rolls_back_on_error() = runTest {
        val cc = initCc()
        cc.transaction { ctx -> ctx.mlsInit(aliceId.toClientId()) }

        val expectedException = RuntimeException("Expected Exception")

        val actualException =
            assertFailsWith<RuntimeException> {
                cc.transaction<Unit> { ctx ->
                    ctx.createConversation(id)
                    throw expectedException
                }
            }

        assertEquals(expectedException, actualException)

        // This would fail with a "Conversation already exists" exception, if the above
        // transaction hadn't been rolled back.
        cc.transaction { ctx -> ctx.createConversation(id) }
    }

    @Test
    fun parallel_transactions_are_performed_serially() = runTest() {
        withContext(Dispatchers.Default) {
            val (alice) = newClients(aliceId)
            val jobs: MutableList<Job> = mutableListOf()
            val token = "t"
            val transactionCount = 3

            // How this test ensures that transactions are performed serially:
            // Each transaction gets the previous token string, adds one token at the end and stores it.
            // If, for instance, the second and third transaction run in parallel they will both get same current
            // token string "tt" and store "ttt".
            // If they execute serially, one will store "ttt" and the other "tttt" (this is what we assert).

            repeat(transactionCount) {
                jobs += launch {
                    alice.transaction { ctx ->
                        delay(100.milliseconds)
                        val data = ctx.getData()?.decodeToString()?.plus(token) ?: token
                        ctx.setData(data.toByteArray())
                    }
                }
            }
            jobs.joinAll()

            val result = alice.transaction { ctx ->
                ctx.getData()?.decodeToString()
            }

            assertEquals(token.repeat(transactionCount), result, "Expected all transactions to complete")
        }
    }

    @Test
    fun errorTypeMapping_should_work() = runTest {
        val (alice) = newClients(aliceId)
        alice.transaction { it.createConversation(id) }
        val expectedException = assertFailsWith<CoreCryptoException.Mls> { alice.transaction { it.createConversation(id) } }
        assertIs<MlsException.ConversationAlreadyExists>(expectedException.exception)
    }

    @Test
    fun getPublicKey_should_return_non_empty_result() = runTest {
        val (alice) = newClients(aliceId)
        assertThat(alice.transaction { it.getPublicKey(Ciphersuite.DEFAULT).value }).isNotEmpty()
    }

    @Test
    fun conversationExists_should_return_true() = runTest {
        val (alice) = newClients(aliceId)
        assertThat(alice.transaction { it.conversationExists(id) }).isFalse()
        alice.transaction { it.createConversation(id) }
        assertThat(alice.transaction { it.conversationExists(id) }).isTrue()
    }

    @Test
    fun calling_generateKeyPackages_should_return_expected_number() = runTest {
        val (alice) = newClients(aliceId)

        // by default
        assertThat(alice.transaction { it.validKeyPackageCount() }).isEqualTo(100.toULong())
        assertThat(alice.transaction { it.generateKeyPackages(200U) }).isNotEmpty().hasSize(200)
        assertThat(alice.transaction { it.validKeyPackageCount() }).isEqualTo(200.toULong())
    }

    @Test
    fun given_new_conversation_when_calling_conversationEpoch_should_return_epoch_0() = runTest {
        val (alice) = newClients(aliceId)
        alice.transaction { it.createConversation(id) }
        assertThat(alice.transaction { it.conversationEpoch(id) }).isEqualTo(0UL)
    }

    @Test
    fun updateKeyingMaterial_should_process_the_commit_message() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }
        bob.transaction { it.updateKeyingMaterial(id) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { it.decryptMessage(groupId, commit) }
        assertThat(decrypted.message).isNull()
        assertThat(decrypted.commitDelay).isNull()
        assertThat(decrypted.senderClientId).isNull()
        assertThat(decrypted.hasEpochChanged).isTrue()
    }

    @Test
    fun addMember_should_allow_joining_a_conversation_with_a_Welcome() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { it.processWelcomeMessage(welcome) }

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id.toString()).isEqualTo(id.value.toHex())
    }

    @Test
    fun joinConversation_should_generate_an_Add_proposal() = runTest {
        val (alice1, alice2, bob) = newClients(aliceId, aliceId2, bobId)

        bob.transaction { it.createConversation(id) }

        val alice1Kp = alice1.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction {
            it.addMember(id, listOf(alice1Kp))
            Unit
        }

        val proposal = alice2.transaction { it.joinConversation(id, 1UL, Ciphersuite.DEFAULT, CredentialType.DEFAULT) }
        bob.transaction { it.decryptMessage(id, proposal) }
        bob.transaction { it.commitPendingProposals(id) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice2.transaction { it.processWelcomeMessage(welcome) }

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id.toString()).isEqualTo(id.value.toHex())
    }

    @Test
    fun encryptMessage_should_encrypt_then_receiver_should_decrypt() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }

        val msg = "Hello World !"
        val ciphertextMsg = alice.transaction { it.encryptMessage(groupId, msg.toPlaintextMessage()) }
        assertThat(ciphertextMsg).isNotEqualTo(msg)

        val plaintextMsg = bob.transaction { it.decryptMessage(groupId, ciphertextMsg).message!! }
        assertThat(String(plaintextMsg)).isNotEmpty().isEqualTo(msg)

        val expectedException = assertFailsWith<CoreCryptoException.Mls>{ bob.transaction { it.decryptMessage(groupId, ciphertextMsg) } }
        assertIs<MlsException.DuplicateMessage>(expectedException.exception)
    }

    @Test
    fun addMember_should_add_members_to_the_MLS_group() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        bob.transaction { it.createConversation(id) }
        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()

        alice.transaction { it.processWelcomeMessage(welcome) }

        val carolKp = carol.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(carolKp)) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { it.decryptMessage(id, commit) }
        assertThat(decrypted.message).isNull()

        val members = alice.transaction { it.members(id) }
        assertThat(
            members.containsAll(listOf(aliceId, bobId, carolId).map { it.toClientId() })
        )
    }

    @Test
    fun addMember_should_return_a_valid_Welcome_message() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()

        val groupId = alice.transaction { it.processWelcomeMessage(welcome) }
        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id.toString()).isEqualTo(id.value.toHex())
    }

    @Test
    fun removeMember_should_remove_members_from_the_MLS_group() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        val carolKp = carol.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp, carolKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val conversationId = alice.transaction { it.processWelcomeMessage(welcome).id }

        val carolMember = listOf(carolId.toClientId())
        bob.transaction { it.removeMember(conversationId, carolMember) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { it.decryptMessage(conversationId, commit) }
        assertThat(decrypted.message).isNull()
    }

    @Test
    fun creating_proposals_and_removing_them() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        alice.transaction { it.createConversation(id) }

        val bobKp = bob.transaction { it.generateKeyPackages(1U).first() }

        // Add proposal
        alice.transaction { it.newAddProposal(id, bobKp) }
        alice.transaction { it.commitPendingProposals(id) }
        val welcome = mockDeliveryService.getLatestWelcome()

        bob.transaction { it.processWelcomeMessage(welcome) }

        val carolKp = carol.transaction { it.generateKeyPackages(1U).first() }

        // Now creating & clearing proposal (indirectly through abort response from delivery service)
        alice.provideTransport(MockMlsTransportAbortProvider())

        val expectedException1 = assertFailsWith<CoreCryptoException.Mls> {
            alice.transaction {
                it.newAddProposal(
                    id,
                    carolKp
                )
            }
        }
        assertIs<MlsException.MessageRejected>(expectedException1.exception)

        val expectedException2 = assertFailsWith<CoreCryptoException.Mls> {
            alice.transaction {
                it.newRemoveProposal(
                    id,
                    bobId.toClientId()
                )
            }
        }
        assertIs<MlsException.MessageRejected>(expectedException2.exception)

        val expectedException3 =
            assertFailsWith<CoreCryptoException.Mls> { alice.transaction { it.newUpdateProposal(id) } }
        assertIs<MlsException.MessageRejected>(expectedException3.exception)

        alice.provideTransport(mockDeliveryService)

        val commitBefore = mockDeliveryService.getLatestCommit()
        // Since all proposals were cleared, this should not produce/send a commit
        alice.transaction { it.commitPendingProposals(id) }
        val commitAfter = mockDeliveryService.getLatestCommit()
        // So this is still the same
        assertThat(commitBefore).isEqualTo(commitAfter)
    }

    @Test
    fun wipeConversation_should_delete_the_conversation_from_the_keystore() = runTest {
        val (alice) = newClients(aliceId)
        alice.transaction { it.createConversation(id) }
        assertThatNoException().isThrownBy {
            runBlocking { alice.transaction { it.wipeConversation(id) } }
        }
    }

    @Test
    fun deriveAvsSecret_should_generate_a_secret_with_the_right_length() = runTest {
        val (alice) = newClients(aliceId)
        alice.transaction { it.createConversation(id) }
        val n = 50
        val secrets = (0 until n).map {
            val secret = alice.transaction { it.deriveAvsSecret(id, 32U) }
            assertThat(secret.value).hasSize(32)
            secret
        }.toSet()
        assertThat(secrets).hasSize(n)
    }
}

fun newClients(vararg clientIds: String) = runBlocking {
    clientIds.map { clientID ->
        val cc = initCc()
        cc.transaction { it.mlsInit(clientID.toClientId()) }
        cc
    }
}

fun initCc(): CoreCrypto = runBlocking {
    val root = Files.createTempDirectory("mls").toFile()
    val keyStore = root.resolve("keystore-${randomIdentifier()}")
    val cc = CoreCrypto(keyStore.absolutePath, "secret")
    cc.provideTransport(MLSTest.mockDeliveryService)
    cc
}

fun randomIdentifier(n: Int = 12): String {
    val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    return (1..n)
        .map { kotlin.random.Random.nextInt(0, charPool.size).let { charPool[it] } }
        .joinToString("")
}

interface MockDeliveryService : MlsTransport {
    suspend fun getLatestCommitBundle(): CommitBundle

    suspend fun getLatestWelcome(): Welcome

    suspend fun getLatestCommit(): MlsMessage
}

class  MockMlsTransportSuccessProvider : MockDeliveryService {

    private var latestCommitBundle: CommitBundle? = null

    override suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse =
        MlsTransportResponse.Success

    override suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse {
        latestCommitBundle = commitBundle
        return MlsTransportResponse.Success
    }

    override suspend fun getLatestCommitBundle(): CommitBundle = latestCommitBundle!!

    override suspend fun getLatestWelcome(): Welcome = getLatestCommitBundle().welcome!!.toWelcome()

    override suspend fun getLatestCommit(): MlsMessage = getLatestCommitBundle().commit.toMlsMessage()
}

class MockMlsTransportAbortProvider : MockDeliveryService {

    override suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse =
        MlsTransportResponse.Abort("Abort provider always aborts")

    override suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse =
        MlsTransportResponse.Abort("Abort provider always aborts")


    override suspend fun getLatestCommitBundle(): CommitBundle =
        throw Exception("Abort provider never stores commit bundles")

    override suspend fun getLatestWelcome(): Welcome =
        throw Exception("Abort provider never stores commit bundles")

    override suspend fun getLatestCommit(): MlsMessage =
        throw Exception("Abort provider never stores commit bundles")
}
