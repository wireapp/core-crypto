@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import com.wire.crypto.testutils.genDatabaseKey
import kotlinx.coroutines.*
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import java.nio.file.Files
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds

class MLSTest {
    companion object {
        internal val id = "JfflcPtUivbg+1U3Iyrzsh5D2ui/OGS5Rvf52ipH5KY=".toGroupId()
        internal const val ALICE_ID = "alice1"
        internal const val BOB_ID = "bob"
        internal const val CAROL_ID = "carol"
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
    fun interaction_with_invalid_context_throws_error() = runTest {
        val cc = initCc()
        var context: CoreCryptoContext? = null

        cc.transaction { ctx -> context = ctx }

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> {
                context!!.mlsInit(ALICE_ID.toClientId())
            }

        assertIs<MlsException.Other>(expectedException.exception)
    }

    @Test
    fun error_is_propagated_by_transaction() = runTest {
        val cc = initCc()
        val expectedException = RuntimeException("Expected Exception")

        val actualException =
            assertFailsWith<RuntimeException> { cc.transaction<Unit> { throw expectedException } }

        // Because internally ForkJoinTask#getThrowableException doesn't necessarily throw exactly the same exception,
        // when it is thrown in another thread (due to the NonCancellable context), we need to compare messages, etc.
        // see: https://hg.openjdk.org/jdk8u/jdk8u/jdk/file/6be37bafb11a/src/share/classes/java/util/concurrent/ForkJoinTask.java#l547
        assertEquals(expectedException.message, actualException.message)
    }

    @Test
    fun transaction_rolls_back_on_error() = runTest {
        val cc = initCc()
        cc.transaction { ctx -> ctx.mlsInit(ALICE_ID.toClientId()) }

        val expectedException = IllegalStateException("Expected Exception")

        val actualException =
            assertFailsWith<RuntimeException> {
                cc.transaction<Unit> { ctx ->
                    ctx.createConversation(id)
                    throw expectedException
                }
            }

        // Because internally ForkJoinTask#getThrowableException doesn't necessarily throw exactly the same exception,
        // when it is thrown in another thread (due to the NonCancellable context), we need to compare messages, etc.
        // see: https://hg.openjdk.org/jdk8u/jdk8u/jdk/file/6be37bafb11a/src/share/classes/java/util/concurrent/ForkJoinTask.java#l547
        assertEquals(expectedException.message, actualException.message)

        // This would fail with a "Conversation already exists" exception, if the above
        // transaction hadn't been rolled back.
        cc.transaction { ctx -> ctx.createConversation(id) }
    }

    @Test
    fun parallel_transactions_are_performed_serially() = runTest {
        withContext(Dispatchers.Default) {
            val (alice) = newClients(ALICE_ID)
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
        val (alice) = newClients(ALICE_ID)
        alice.transaction { it.createConversation(id) }
        val expectedException = assertFailsWith<CoreCryptoException.Mls> { alice.transaction { it.createConversation(id) } }
        assertIs<MlsException.ConversationAlreadyExists>(expectedException.exception)
    }

    @Test
    fun getPublicKey_should_return_non_empty_result() = runTest {
        val (alice) = newClients(ALICE_ID)
        assertThat(alice.transaction { it.getPublicKey(Ciphersuite.DEFAULT) }).isNotEmpty()
    }

    @Test
    fun conversationExists_should_return_true() = runTest {
        val (alice) = newClients(ALICE_ID)
        assertThat(alice.transaction { it.conversationExists(id) }).isFalse()
        alice.transaction { it.createConversation(id) }
        assertThat(alice.transaction { it.conversationExists(id) }).isTrue()
    }

    @Test
    fun calling_generateKeyPackages_should_return_expected_number() = runTest {
        val (alice) = newClients(ALICE_ID)

        // by default
        assertThat(alice.transaction { it.validKeyPackageCount() }).isEqualTo(100.toULong())
        assertThat(alice.transaction { it.generateKeyPackages(200U) }).isNotEmpty().hasSize(200)
        assertThat(alice.transaction { it.validKeyPackageCount() }).isEqualTo(200.toULong())
    }

    @Test
    fun given_new_conversation_when_calling_conversationEpoch_should_return_epoch_0() = runTest {
        val (alice) = newClients(ALICE_ID)
        alice.transaction { it.createConversation(id) }
        assertThat(alice.transaction { it.conversationEpoch(id) }).isEqualTo(0UL)
    }

    @Test
    fun updateKeyingMaterial_should_process_the_commit_message() = runTest {
        val (alice, bob) = newClients(ALICE_ID, BOB_ID)

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
        val (alice, bob) = newClients(ALICE_ID, BOB_ID)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { it.processWelcomeMessage(welcome) }

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id).isEqualTo(id)
    }

    @Test
    fun encryptMessage_should_encrypt_then_receiver_should_decrypt() = runTest {
        val (alice, bob) = newClients(ALICE_ID, BOB_ID)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }

        val msg = "Hello World !".toByteArray()
        val ciphertextMsg = alice.transaction { it.encryptMessage(groupId, msg) }
        assertThat(ciphertextMsg).isNotEqualTo(msg)

        val plaintextMsg = bob.transaction { it.decryptMessage(groupId, ciphertextMsg).message!! }
        assertThat(plaintextMsg).isNotEmpty().isEqualTo(msg)

        val expectedException = assertFailsWith<CoreCryptoException.Mls> { bob.transaction { it.decryptMessage(groupId, ciphertextMsg) } }
        assertIs<MlsException.DuplicateMessage>(expectedException.exception)
    }

    @Test
    fun addMember_should_add_members_to_the_MLS_group() = runTest {
        val (alice, bob, carol) = newClients(ALICE_ID, BOB_ID, CAROL_ID)

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
            members.containsAll(listOf(ALICE_ID, BOB_ID, CAROL_ID).map { it.toClientId() })
        )
    }

    @Test
    fun addMember_should_return_a_valid_Welcome_message() = runTest {
        val (alice, bob) = newClients(ALICE_ID, BOB_ID)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()

        val groupId = alice.transaction { it.processWelcomeMessage(welcome) }
        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id).isEqualTo(id)
    }

    @Test
    fun removeMember_should_remove_members_from_the_MLS_group() = runTest {
        val (alice, bob, carol) = newClients(ALICE_ID, BOB_ID, CAROL_ID)

        bob.transaction { it.createConversation(id) }

        val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
        val carolKp = carol.transaction { it.generateKeyPackages(1U).first() }
        bob.transaction { it.addMember(id, listOf(aliceKp, carolKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val conversationId = alice.transaction { it.processWelcomeMessage(welcome).id }

        val carolMember = listOf(CAROL_ID.toClientId())
        bob.transaction { it.removeMember(conversationId, carolMember) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { it.decryptMessage(conversationId, commit) }
        assertThat(decrypted.message).isNull()
    }

    @Test
    fun wipeConversation_should_delete_the_conversation_from_the_keystore() = runTest {
        val (alice) = newClients(ALICE_ID)
        alice.transaction { it.createConversation(id) }
        assertThatNoException().isThrownBy {
            runBlocking { alice.transaction { it.wipeConversation(id) } }
        }
    }

    @Test
    fun givenTransactionRunsSuccessfully_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val coreCrypto = initCc()
        val someWork = Job()
        val firstTransactionJob = launch {
            coreCrypto.transaction {
                someWork.complete()
            }
        }
        firstTransactionJob.join()

        var didRun = false
        val secondTransactionJob = launch {
            coreCrypto.transaction {
                didRun = true
            }
        }
        secondTransactionJob.join()
        assertTrue { didRun }
    }

    @Test
    fun givenTransactionIsCancelled_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val coreCrypto = initCc()

        val firstTransactionJob = launch {
            coreCrypto.transaction {
                this@launch.cancel()
            }
        }
        firstTransactionJob.join()

        var didRun = false
        val secondTransactionJob = launch {
            coreCrypto.transaction {
                didRun = true
            }
        }
        secondTransactionJob.join()
        assertTrue { didRun }
    }

    @Test
    fun deriveAvsSecret_should_generate_a_secret_with_the_right_length() = runTest {
        val (alice) = newClients(ALICE_ID)
        alice.transaction { it.createConversation(id) }
        val n = 50
        val secrets = (0 until n).map {
            val secret = alice.transaction { it.deriveAvsSecret(id, 32U) }
            assertThat(secret.value).hasSize(32)
            secret
        }.toSet()
        assertThat(secrets).hasSize(n)
    }

    @Test
    fun registerEpochObserver_should_notify_observer_on_new_epoch(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            // Set up the observer. this just keeps a list of all observations.
            data class EpochChanged(val conversationId: MLSGroupId, val epoch: ULong)

            class Observer : EpochObserver {
                val observedEvents = emptyList<EpochChanged>().toMutableList()

                override suspend fun epochChanged(conversationId: MLSGroupId, epoch: ULong) {
                    observedEvents.add(EpochChanged(conversationId, epoch))
                }
            }
            val bobObserver = Observer()
            val aliceObserver = Observer()

            // Set up the conversation in one transaction
            val (alice, bob) = newClients(ALICE_ID, BOB_ID)
            bob.transaction { it.createConversation(id) }

            // Register observers
            bob.registerEpochObserver(scope, bobObserver)
            alice.registerEpochObserver(scope, aliceObserver)

            // In another transaction, change the epoch
            bob.transaction { it.updateKeyingMaterial(id) }

            // Alice joins the group
            val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
            bob.transaction { it.addMember(id, listOf(aliceKp)) }
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }

            // Change the epoch again, this should be seen by both observers
            bob.transaction { it.updateKeyingMaterial(id) }
            val commit = mockDeliveryService.getLatestCommit()
            alice.transaction { it.decryptMessage(groupId, commit) }

            // Bob's observer must have observed all epoch change events, Alice's observer saw only the
            // last one
            assertEquals(3, bobObserver.observedEvents.size, "we triggered exactly 3 epoch changes and must have observed that")
            assertEquals(1, aliceObserver.observedEvents.size, "we triggered exactly 1 epoch change and must have observed that")

            assertTrue(
                bobObserver.observedEvents.all { it.conversationId.value == id.value },
                "the events observed by bob must be for this conversation"
            )
            assertTrue(
                aliceObserver.observedEvents.all { it.conversationId.value == id.value },
                "the event observed by alice must be for this conversation"
            )
        }
    }

    @Test
    fun registerHistoryObserver_should_notify_observer_on_new_secret(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            // Set up the observer. this just keeps a list of all observations.
            data class HistorySecretEvent(val conversationId: MLSGroupId, val id: ClientId)

            class Observer : HistoryObserver {
                val observedEvents = emptyList<HistorySecretEvent>().toMutableList()

                override suspend fun historyClientCreated(
                    conversationId: MLSGroupId,
                    secret: HistorySecret
                ) {
                    observedEvents.add(HistorySecretEvent(conversationId, secret.clientId))
                }
            }
            val bobObserver = Observer()
            val aliceObserver = Observer()

            // Set up the conversation in one transaction
            val (alice, bob) = newClients(ALICE_ID, BOB_ID)
            val aliceKp = alice.transaction { it.generateKeyPackages(1U).first() }
            bob.transaction {
                it.createConversation(id)
                it.addMember(id, listOf(aliceKp))
            }

            // Alice joins the group
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { it.processWelcomeMessage(welcome).id }

            // Register observers
            bob.registerHistoryObserver(scope, bobObserver)
            alice.registerHistoryObserver(scope, aliceObserver)

            // History sharing is disabled by default
            assertFalse(bob.isHistorySharingEnabled(id))

            // In another transaction, enable history sharing
            bob.transaction { it.enableHistorySharing(id) }

            // Before Alice received the commit, history sharing is only enabled for Bob
            assertTrue(bob.isHistorySharingEnabled(id))
            assertFalse(alice.isHistorySharingEnabled(id))

            val commit = mockDeliveryService.getLatestCommit()
            alice.transaction { it.decryptMessage(groupId, commit) }
            assertTrue(alice.isHistorySharingEnabled(id))

            // Bob's observer must have observed the history secret changes, Alice's should not have observed anything
            assertEquals(1, bobObserver.observedEvents.size, "bob triggered exactly 1 history secret changes and must have observed that")
            assertEquals(
                0,
                aliceObserver.observedEvents.size,
                "alice did not trigger any history secret changes and must not have observed that"
            )
            val expected = id
            assertTrue(
                bobObserver.observedEvents.all { it.conversationId == expected },
                "the events observed by bob must be for this conversation"
            )
        }
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
    val key = genDatabaseKey()
    val cc = CoreCrypto(keyStore.absolutePath, key)
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

    suspend fun getLatestCommit(): ByteArray
}

class MockMlsTransportSuccessProvider : MockDeliveryService {
    private var latestCommitBundle: CommitBundle? = null

    override suspend fun sendMessage(mlsMessage: ByteArray): MlsTransportResponse =
        MlsTransportResponse.Success

    override suspend fun sendCommitBundle(commitBundle: CommitBundle): MlsTransportResponse {
        latestCommitBundle = commitBundle
        return MlsTransportResponse.Success
    }

    override suspend fun prepareForTransport(historySecret: HistorySecret): MlsTransportData {
        return MlsTransportData("secret".encodeToByteArray())
    }

    override suspend fun getLatestCommitBundle(): CommitBundle = latestCommitBundle!!

    override suspend fun getLatestWelcome(): Welcome = getLatestCommitBundle().welcome!!

    override suspend fun getLatestCommit(): ByteArray = getLatestCommitBundle().commit
}
