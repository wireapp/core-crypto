@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import kotlinx.coroutines.*
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import testutils.*
import java.nio.file.Files
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds

class MLSTest : HasMockDeliveryService() {
    companion object {
        private val id: ConversationId = genConversationId()
    }

    @BeforeTest
    fun setup() {
        setupMocks()
    }

    @Test
    fun set_client_data_persists() = runTest {
        val cc = initCc(this@MLSTest)

        val data = "my message processing checkpoint".toByteArray()

        cc.transaction { ctx ->
            assertThat(ctx.getData()).isNull()
            ctx.setData(data)
        }

        cc.transaction { ctx -> assertThat(ctx.getData()).isEqualTo(data) }
    }

    @Test
    fun interaction_with_invalid_context_throws_error() = runTest {
        val cc = initCc(this@MLSTest)
        var context: CoreCryptoContext? = null

        cc.transaction { ctx -> context = ctx }

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> {
                context!!.mlsInitShort(genClientId())
            }

        assertIs<MlsException.Other>(expectedException.mlsError)
    }

    @Test
    fun error_is_propagated_by_transaction() = runTest {
        val cc = initCc(this@MLSTest)
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
        val cc = initCc(this@MLSTest)
        cc.transaction { ctx -> ctx.mlsInitShort(genClientId()) }

        val expectedException = IllegalStateException("Expected Exception")

        val actualException =
            assertFailsWith<RuntimeException> {
                cc.transaction<Unit> { ctx ->
                    ctx.createConversationShort(id)
                    throw expectedException
                }
            }

        // Because internally ForkJoinTask#getThrowableException doesn't necessarily throw exactly the same exception,
        // when it is thrown in another thread (due to the NonCancellable context), we need to compare messages, etc.
        // see: https://hg.openjdk.org/jdk8u/jdk8u/jdk/file/6be37bafb11a/src/share/classes/java/util/concurrent/ForkJoinTask.java#l547
        assertEquals(expectedException.message, actualException.message)

        // This would fail with a "Conversation already exists" exception, if the above
        // transaction hadn't been rolled back.
        cc.transaction { ctx -> ctx.createConversationShort(id) }
    }

    @Test
    fun parallel_transactions_are_performed_serially() = runTest {
        withContext(Dispatchers.Default) {
            val (alice) = newClients(this@MLSTest, genClientId())
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
        val (alice) = newClients(this@MLSTest, genClientId())
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        val expectedException = assertFailsWith<CoreCryptoException.Mls> { alice.transaction { ctx -> ctx.createConversationShort(id) } }
        assertIs<MlsException.ConversationAlreadyExists>(expectedException.mlsError)
    }

    @Test
    fun getPublicKey_should_return_non_empty_result() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())
        assertThat(alice.transaction { ctx -> ctx.clientPublicKey(CIPHERSUITE_DEFAULT, CREDENTIAL_TYPE_DEFAULT) }).isNotEmpty()
    }

    @Test
    fun conversationExists_should_return_true() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())
        assertThat(alice.transaction { ctx -> ctx.conversationExists(id) }).isFalse()
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        assertThat(alice.transaction { ctx -> ctx.conversationExists(id) }).isTrue()
    }

    @Test
    fun calling_generateKeyPackages_should_return_expected_number() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())

        // by default, no key packages are generated
        assertThat(
            alice.transaction { ctx ->
                ctx.getKeypackages().size
            }
        ).isEqualTo(0)
        assertThat(alice.transaction { ctx -> ctx.clientKeypackagesShort(200U) }).isNotEmpty().hasSize(200)
        assertThat(
            alice.transaction { ctx ->
                ctx.getKeypackages().size
            }
        ).isEqualTo(200)
    }

    @Test
    fun given_new_conversation_when_calling_conversationEpoch_should_return_epoch_0() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        assertThat(alice.transaction { ctx -> ctx.conversationEpoch(id) }).isEqualTo(0UL)
    }

    @Test
    fun updateKeyingMaterial_should_process_the_commit_message() = runTest {
        val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())

        bob.transaction { ctx -> ctx.createConversationShort(id) }

        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT).id }
        bob.transaction { ctx -> ctx.updateKeyingMaterial(id) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(groupId, commit) }
        assertThat(decrypted.message).isNull()
        assertThat(decrypted.commitDelay).isNull()
        assertThat(decrypted.senderClientId).isNull()
        assertThat(decrypted.hasEpochChanged).isTrue()
    }

    @Test
    fun addClientsToConversation_should_allow_joining_a_conversation_with_a_Welcome() = runTest {
        val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())

        bob.transaction { ctx -> ctx.createConversationShort(id) }

        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT) }

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id).isEqualTo(id)
    }

    @Test
    fun encryptMessage_should_encrypt_then_receiver_should_decrypt() = runTest {
        val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())

        bob.transaction { ctx -> ctx.createConversationShort(id) }

        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT).id }

        val msg = "Hello World !".toByteArray()
        val ciphertextMsg = alice.transaction { ctx -> ctx.encryptMessage(groupId, msg) }
        assertThat(ciphertextMsg).isNotEqualTo(msg)

        val plaintextMsg = bob.transaction { ctx -> ctx.decryptMessage(groupId, ciphertextMsg).message!! }
        assertThat(plaintextMsg).isNotEmpty().isEqualTo(msg)

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> { bob.transaction { ctx -> ctx.decryptMessage(groupId, ciphertextMsg) } }
        assertIs<MlsException.DuplicateMessage>(expectedException.mlsError)
    }

    @Test
    fun addClientsToConversation_should_add_members_to_the_MLS_group() = runTest {
        val aliceId = genClientId()
        val bobId = genClientId()
        val carolId = genClientId()
        val (alice, bob, carol) = newClients(this@MLSTest, aliceId, bobId, carolId)

        bob.transaction { ctx -> ctx.createConversationShort(id) }
        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()

        alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT) }

        val carolKp = carol.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(carolKp)) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(id, commit) }
        assertThat(decrypted.message).isNull()

        val members = alice.transaction { ctx -> ctx.getClientIds(id) }
        assertThat(
            members.containsAll(listOf(aliceId, bobId, carolId))
        )
    }

    @Test
    fun addClientsToConversation_should_return_a_valid_Welcome_message() = runTest {
        val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())

        bob.transaction { ctx -> ctx.createConversationShort(id) }

        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()

        val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT) }
        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(groupId.id).isEqualTo(id)
    }

    @Test
    fun removeMember_should_remove_members_from_the_MLS_group() = runTest {
        val carolId = genClientId()
        val (alice, bob, carol) = newClients(this@MLSTest, genClientId(), genClientId(), carolId)

        bob.transaction { ctx -> ctx.createConversationShort(id) }

        val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        val carolKp = carol.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
        bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp, carolKp)) }
        val welcome = mockDeliveryService.getLatestWelcome()
        val conversationId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT).id }

        val carolMember = listOf(carolId)
        bob.transaction { ctx -> ctx.removeClientsFromConversation(conversationId, carolMember) }
        val commit = mockDeliveryService.getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(conversationId, commit) }
        assertThat(decrypted.message).isNull()
    }

    @Test
    fun wipeConversation_should_delete_the_conversation_from_the_keystore() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        assertThatNoException().isThrownBy {
            runBlocking { alice.transaction { ctx -> ctx.wipeConversation(id) } }
        }
    }

    @Test
    fun givenTransactionRunsSuccessfully_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val coreCrypto = initCc(this@MLSTest)
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
        val coreCrypto = initCc(this@MLSTest)

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
    fun exportSecretKey_should_generate_a_secret_with_the_right_length() = runTest {
        val (alice) = newClients(this@MLSTest, genClientId())
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        val n = 50
        val secrets = (0 until n).map {
            val secret = alice.transaction { ctx -> ctx.exportSecretKey(id, 32U) }.copyBytes()
            assertThat(secret).hasSize(32)
            secret
        }.toSet()
        assertThat(secrets).hasSize(n)
    }

    @Test
    fun registerEpochObserver_should_notify_observer_on_new_epoch(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            // Set up the observer. this just keeps a list of all observations.
            data class EpochChanged(val conversationId: ConversationId, val epoch: ULong)

            class Observer : EpochObserver {
                val observedEvents = emptyList<EpochChanged>().toMutableList()

                override suspend fun epochChanged(conversationId: ConversationId, epoch: ULong) {
                    observedEvents.add(EpochChanged(conversationId, epoch))
                }
            }
            val bobObserver = Observer()
            val aliceObserver = Observer()

            // Set up the conversation in one transaction
            val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())
            bob.transaction { ctx -> ctx.createConversationShort(id) }

            // Register observers
            bob.registerEpochObserver(scope, bobObserver)
            alice.registerEpochObserver(scope, aliceObserver)

            // In another transaction, change the epoch
            bob.transaction { ctx -> ctx.updateKeyingMaterial(id) }

            // Alice joins the group
            val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
            bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT).id }

            // Change the epoch again, this should be seen by both observers
            bob.transaction { ctx -> ctx.updateKeyingMaterial(id) }
            val commit = mockDeliveryService.getLatestCommit()
            alice.transaction { ctx -> ctx.decryptMessage(groupId, commit) }

            // Bob's observer must have observed all epoch change events, Alice's observer saw only the
            // last one
            assertEquals(3, bobObserver.observedEvents.size, "we triggered exactly 3 epoch changes and must have observed that")
            assertEquals(1, aliceObserver.observedEvents.size, "we triggered exactly 1 epoch change and must have observed that")

            assertTrue(
                bobObserver.observedEvents.all { ctx -> ctx.conversationId == id },
                "the events observed by bob must be for this conversation"
            )
            assertTrue(
                aliceObserver.observedEvents.all { ctx -> ctx.conversationId == id },
                "the event observed by alice must be for this conversation"
            )
        }
    }

    @Test
    fun registerHistoryObserver_should_notify_observer_on_new_secret(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            // Set up the observer. this just keeps a list of all observations.
            data class HistorySecretEvent(val conversationId: ConversationId, val id: ClientId)

            class Observer : HistoryObserver {
                val observedEvents = emptyList<HistorySecretEvent>().toMutableList()

                override suspend fun historyClientCreated(
                    conversationId: ConversationId,
                    secret: HistorySecret
                ) {
                    observedEvents.add(HistorySecretEvent(conversationId, secret.clientId))
                }
            }
            val bobObserver = Observer()
            val aliceObserver = Observer()

            // Set up the conversation in one transaction
            val (alice, bob) = newClients(this@MLSTest, genClientId(), genClientId())
            val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1U).first() }
            bob.transaction {
                it.createConversationShort(id)
                it.addClientsToConversation(id, listOf(aliceKp))
            }

            // Alice joins the group
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome, CUSTOM_CONFIGURATION_DEFAULT).id }

            // Register observers
            bob.registerHistoryObserver(scope, bobObserver)
            alice.registerHistoryObserver(scope, aliceObserver)

            // History sharing is disabled by default
            assertFalse(bob.isHistorySharingEnabled(id))

            // In another transaction, enable history sharing
            bob.transaction { ctx -> ctx.enableHistorySharing(id) }

            // Before Alice received the commit, history sharing is only enabled for Bob
            assertTrue(bob.isHistorySharingEnabled(id))
            assertFalse(alice.isHistorySharingEnabled(id))

            val commit = mockDeliveryService.getLatestCommit()
            alice.transaction { ctx: CoreCryptoContext -> ctx.decryptMessage(groupId, commit) }
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
                bobObserver.observedEvents.all { ctx -> ctx.conversationId == expected },
                "the events observed by bob must be for this conversation"
            )
        }
    }

    @Test
    fun can_construct_basic_credential(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, genClientId())
            assertEquals(credential.type(), CredentialType.BASIC)
            assertEquals<ULong>(credential.earliestValidity(), 0u)
        }
    }

    @Test
    fun can_add_basic_credential(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val ref = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            assertEquals(ref.type(), CredentialType.BASIC)
            assertNotEquals(ref.earliestValidity(), 0uL)

            val allCredentials = cc.transaction { ctx -> ctx.getCredentials() }
            assertThat(allCredentials).hasSize(1)
        }
    }

    @Test
    fun can_remove_basic_credential(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val ref = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            cc.transaction { ctx ->
                ctx.removeCredential(ref)
            }

            val allCredentials = cc.transaction { ctx -> ctx.getCredentials() }
            assertThat(allCredentials).hasSize(0)
        }
    }

    @Test
    fun can_search_credentials_by_ciphersuite(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val ciphersuite1 = Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            val credential1 = Credential.basic(ciphersuite1, clientId)

            val ciphersuite2 =
                Ciphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519
            val credential2 = Credential.basic(ciphersuite2, clientId)

            val cc = initCc(this@MLSTest)
            cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential1)
                ctx.addCredential(credential2)
            }

            val results1 = cc.transaction { ctx ->
                ctx.findCredentials(
                    clientId = null,
                    publicKey = null,
                    ciphersuite = ciphersuite1,
                    credentialType = null,
                    earliestValidity = null
                )
            }
            val results2 = cc.transaction { ctx ->
                ctx.findCredentials(
                    clientId = null,
                    publicKey = null,
                    ciphersuite = ciphersuite2,
                    credentialType = null,
                    earliestValidity = null
                )
            }

            assertThat(results1).hasSize(1)
            assertThat(results2).hasSize(1)
            assertNotEquals(results1[0], results2[0])
        }
    }

    @Test
    fun can_create_keypackage(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val credentialRef = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            val keyPackage = cc.transaction { ctx ->
                ctx.generateKeypackage(credentialRef)
            }

            assertNotNull(keyPackage)
        }
    }

    @Test
    fun can_serialize_keypackage(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val credentialRef = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            val keyPackage = cc.transaction { ctx ->
                ctx.generateKeypackage(credentialRef)
            }

            val bytes = keyPackage.serialize()
            assertNotNull(bytes)
            assertTrue(bytes.isNotEmpty())

            // roundtrip
            val kp2 = Keypackage(bytes)
            val bytes2 = kp2.serialize()

            assertEquals(bytes.toList(), bytes2.toList())
        }
    }

    @Test
    fun can_retrieve_keypackages_in_bulk(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val credentialRef = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            cc.transaction { ctx ->
                ctx.generateKeypackage(credentialRef)
            }

            val keyPackages = cc.transaction { ctx ->
                ctx.getKeypackages()
            }

            assertNotNull(keyPackages)
            assertThat(keyPackages).hasSize(1)
            assertNotNull(keyPackages[0])
        }
    }

    @Test
    fun can_remove_keypackage(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential = Credential.basic(CIPHERSUITE_DEFAULT, clientId)

            val cc = initCc(this@MLSTest)
            val credentialRef = cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                ctx.addCredential(credential)
            }

            // add a kp which will not be removed
            cc.transaction { ctx ->
                ctx.generateKeypackage(credentialRef)
            }

            // add a kp which will be removed
            val keyPackage = cc.transaction { ctx ->
                ctx.generateKeypackage(credentialRef)
            }

            // remove the keypackage
            cc.transaction { ctx ->
                ctx.removeKeypackage(keyPackage.ref())
            }

            val keyPackages = cc.transaction { ctx ->
                ctx.getKeypackages()
            }

            assertNotNull(keyPackages)
            assertThat(keyPackages).hasSize(1)
        }
    }

    @Test
    fun can_remove_keypackages_by_credentialref(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val clientId = genClientId()
            val credential1 = Credential.basic(
                Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
                clientId
            )
            val credential2 = Credential.basic(
                Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                clientId
            )

            val cc = initCc(this@MLSTest)

            cc.transaction { ctx ->
                ctx.mlsInitShort(clientId)
                val cref1 = ctx.addCredential(credential1)
                val cref2 = ctx.addCredential(credential2)

                val keypackagesPerCredential = 2
                for (cref in listOf(cref1, cref2)) {
                    repeat(keypackagesPerCredential) {
                        ctx.generateKeypackage(cref)
                    }
                }

                val kpsBeforeRemoval = ctx.getKeypackages()
                assertThat(kpsBeforeRemoval).hasSize(keypackagesPerCredential * 2)

                // remove all keypackages for one of the credentials
                ctx.removeKeypackagesFor(cref1)

                val kps = ctx.getKeypackages()
                assertThat(kps).hasSize(keypackagesPerCredential)
            }
        }
    }
}
