@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.crypto

import kotlinx.coroutines.*
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import testutils.*
import kotlin.collections.toList
import kotlin.test.*
import kotlin.time.Duration.Companion.milliseconds

class MLSTest {
    @Test
    fun set_client_data_persists() = runTest {
        val cc = CoreCrypto(newDatabase())

        val data = "my message processing checkpoint".toByteArray()

        cc.transaction { ctx ->
            assertThat(ctx.getData()).isNull()
            ctx.setData(data)
        }

        cc.transaction { ctx -> assertThat(ctx.getData()).isEqualTo(data) }
    }

    @Test
    fun interaction_with_invalid_context_throws_error() = runTest {
        val cc = CoreCrypto(newDatabase())
        var context: CoreCryptoContext? = null

        cc.transaction { ctx -> context = ctx }

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> {
                context!!.mlsInit(genClientId(), MockMlsTransportSuccessProvider.getInstance())
            }

        assertIs<MlsException.Other>(expectedException.mlsError)
    }

    @Test
    fun error_is_propagated_by_transaction() = runTest {
        val cc = CoreCrypto(newDatabase())
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
        val cc = ccInit()

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

    @Suppress("InjectDispatcher")
    @Test
    fun parallel_transactions_are_performed_serially() = runTest {
        withContext(Dispatchers.Default) {
            val alice = ccInit()
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
        val alice = ccInit()
        val conversationId = createConversation(alice)
        val expectedException = assertFailsWith<CoreCryptoException.Mls> {
            alice.transaction { ctx -> ctx.createConversationShort(conversationId) }
        }
        assertIs<MlsException.ConversationAlreadyExists>(expectedException.mlsError)
    }

    @Test
    fun findCredentials_should_return_non_empty_result() = runTest {
        val clientId = genClientId()
        val alice = ccInit(CcInitOptions.WithBasicCredential(CIPHERSUITE_DEFAULT, clientId))
        assertThat(alice.transaction { it.findCredentials(clientId, null, null, null, null) }).isNotEmpty()
    }

    @Test
    fun conversationExists_should_return_true() = runTest {
        val alice = ccInit()
        assertThat(alice.transaction { ctx -> ctx.conversationExists(id) }).isFalse()
        alice.transaction { ctx -> ctx.createConversationShort(id) }
        assertThat(alice.transaction { ctx -> ctx.conversationExists(id) }).isTrue()
    }

    @Test
    fun calling_generateKeyPackages_should_return_expected_number() = runTest {
        val alice = ccInit()

        // by default, no key packages are generated
        assertThat(
            alice.transaction { ctx ->
                ctx.getKeyPackages().size
            }
        ).isEqualTo(0)
        assertThat(alice.transaction { ctx -> ctx.clientKeypackagesShort(200U) }).isNotEmpty().hasSize(200)
        assertThat(
            alice.transaction { ctx ->
                ctx.getKeyPackages().size
            }
        ).isEqualTo(200)
    }

    @Test
    fun given_new_conversation_when_calling_conversationEpoch_should_return_epoch_0() = runTest {
        val alice = ccInit()
        val id = createConversation(alice)
        assertThat(alice.transaction { ctx -> ctx.conversationEpoch(id) }).isEqualTo(0UL)
    }

    @Test
    fun updateKeyingMaterial_should_process_the_commit_message() = runTest {
        val alice = ccInit()
        val bob = ccInit()
        val conversationId = createConversation(bob)

        val groupId = invite(bob, alice, conversationId)
        bob.transaction { ctx -> ctx.updateKeyingMaterial(groupId) }
        val commit = MockMlsTransportSuccessProvider.getInstance().getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(groupId, commit) }
        assertThat(decrypted.message).isNull()
        assertThat(decrypted.commitDelay).isNull()
        assertThat(decrypted.senderClientId).isNull()
    }

    @Test
    fun addClientsToConversation_should_allow_joining_a_conversation_with_a_Welcome() = runTest {
        val alice = ccInit()
        val bob = ccInit()

        val conversationId = createConversation(bob)
        val groupId = invite(bob, alice, conversationId)

        assertThat(groupId).isEqualTo(conversationId)
    }

    @Test
    fun encryptMessage_should_encrypt_then_receiver_should_decrypt() = runTest {
        val alice = ccInit()
        val bob = ccInit()

        val conversationId = createConversation(bob)
        val groupId = invite(bob, alice, conversationId)

        val msg = "Hello World !".toByteArray()
        val ciphertextMsg = alice.transaction { ctx -> ctx.encryptMessage(groupId, msg) }
        assertThat(ciphertextMsg).isNotEqualTo(msg)

        val plaintextMsg = bob.transaction { ctx -> ctx.decryptMessage(groupId, ciphertextMsg).message!! }
        assertThat(plaintextMsg).isNotEmpty().isEqualTo(msg)

        val expectedException =
            assertFailsWith<CoreCryptoException.Mls> {
                bob.transaction { ctx -> ctx.decryptMessage(groupId, ciphertextMsg) }
            }
        assertIs<MlsException.DuplicateMessage>(expectedException.mlsError)
    }

    @Test
    fun addClientsToConversation_should_add_members_to_the_MLS_group() = runTest {
        val aliceId = genClientId()
        val alice = ccInit(CcInitOptions.WithBasicCredential(CIPHERSUITE_DEFAULT, aliceId))
        val bobId = genClientId()
        val bob = ccInit(CcInitOptions.WithBasicCredential(CIPHERSUITE_DEFAULT, bobId))
        val carolId = genClientId()
        val carol = ccInit(CcInitOptions.WithBasicCredential(CIPHERSUITE_DEFAULT, carolId))

        val conversationId = createConversation(bob)
        invite(bob, alice, conversationId)

        invite(bob, carol, conversationId)
        val commit = MockMlsTransportSuccessProvider.getInstance().getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(conversationId, commit) }
        assertThat(decrypted.message).isNull()

        val members = alice.transaction { ctx -> ctx.getClientIds(conversationId) }
        assertThat(members).containsAll(listOf(aliceId, bobId, carolId))
    }

    @Test
    fun addClientsToConversation_should_return_a_valid_Welcome_message() = runTest {
        val alice = ccInit()
        val bob = ccInit()

        val id = createConversation(bob)

        val groupId = invite(bob, alice, id)
        assertThat(groupId).isEqualTo(id)
    }

    @Test
    fun removeMember_should_remove_members_from_the_MLS_group() = runTest {
        val alice = ccInit()
        val bob = ccInit()
        val carolId = genClientId()
        val carol = ccInit(CcInitOptions.WithBasicCredential(CIPHERSUITE_DEFAULT, carolId))
        val conversationId = createConversation(bob)
        invite(bob, alice, conversationId)
        invite(bob, carol, conversationId)
        alice.transaction { ctx ->
            ctx.decryptMessage(conversationId, MockMlsTransportSuccessProvider.getInstance().getLatestCommit())
        }

        val carolMember = listOf(carolId)
        bob.transaction { ctx -> ctx.removeClientsFromConversation(conversationId, carolMember) }
        val commit = MockMlsTransportSuccessProvider.getInstance().getLatestCommit()

        val decrypted = alice.transaction { ctx -> ctx.decryptMessage(conversationId, commit) }
        assertThat(decrypted.message).isNull()
    }

    @Test
    fun wipeConversation_should_delete_the_conversation_from_the_keystore() = runTest {
        val alice = ccInit()
        val conversationId = createConversation(alice)
        assertThatNoException().isThrownBy {
            runBlocking { alice.transaction { ctx -> ctx.wipeConversation(conversationId) } }
        }
    }

    @Test
    fun givenTransactionRunsSuccessfully_thenShouldBeAbleToFinishOtherTransactions() = runTest {
        val coreCrypto = ccInit(CcInitOptions.WithoutBasicCredential())
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
        val coreCrypto = ccInit(CcInitOptions.WithoutBasicCredential())

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
        val alice = ccInit()
        val conversationId = createConversation(alice)
        val n = 50
        val secrets = (0 until n).map {
            val secret = alice.transaction { ctx -> ctx.exportSecretKey(conversationId, 32U) }.copyBytes()
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
            val alice = ccInit()
            val bob = ccInit()
            val conversationId = createConversation(bob)

            // Register observers
            bob.registerEpochObserver(scope, bobObserver)
            alice.registerEpochObserver(scope, aliceObserver)

            // In another transaction, change the epoch
            bob.transaction { ctx -> ctx.updateKeyingMaterial(conversationId) }

            // Alice joins the group
            invite(bob, alice, conversationId)

            // Change the epoch again, this should be seen by both observers
            bob.transaction { ctx -> ctx.updateKeyingMaterial(conversationId) }
            val commit = MockMlsTransportSuccessProvider.getInstance().getLatestCommit()
            alice.transaction { ctx -> ctx.decryptMessage(conversationId, commit) }

            // Bob's observer must have observed all epoch change events, Alice's observer saw only the
            // last one
            assertEquals(
                3,
                bobObserver.observedEvents.size,
                "we triggered exactly 3 epoch changes and must have observed that"
            )
            assertEquals(
                1,
                aliceObserver.observedEvents.size,
                "we triggered exactly 1 epoch change and must have observed that"
            )

            assertTrue(
                bobObserver.observedEvents.all { ctx -> ctx.conversationId == conversationId },
                "the events observed by bob must be for this conversation"
            )
            assertTrue(
                aliceObserver.observedEvents.all { ctx -> ctx.conversationId == conversationId },
                "the event observed by alice must be for this conversation"
            )
        }
    }

    @Test
    fun epochObserverEvent_shouldAllowReadingData(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val alice = ccInit()

            data class ObserverEvent(val eventEpoch: ULong, val conversationEpoch: ULong)

            class Observer : EpochObserver {
                val observedEvents = emptyList<CompletableDeferred<ObserverEvent>>().toMutableList()

                fun expectEvent(): CompletableDeferred<ObserverEvent> =
                    CompletableDeferred<ObserverEvent>().also { observedEvents.add(it) }

                override suspend fun epochChanged(conversationId: ConversationId, epoch: ULong) {
                    val deferredEvent = observedEvents.firstOrNull { !it.isCompleted } ?: expectEvent()
                    val conversationEpoch = alice.conversationEpoch(conversationId)
                    val event = ObserverEvent(epoch, conversationEpoch)
                    deferredEvent.complete(event)
                }
            }

            val aliceObserver = Observer()

            val conversationId = createConversation(alice)
            val initialEpoch = alice.conversationEpoch(conversationId)

            alice.registerEpochObserver(scope, aliceObserver)

            val expectedEvent = aliceObserver.expectEvent()
            alice.transaction { it.updateKeyingMaterial(conversationId) }
            val observedEvent = expectedEvent.await()
            val laterEpoch = alice.conversationEpoch(conversationId)

            assertEquals(initialEpoch + 1U, laterEpoch)
            assertEquals(
                1,
                aliceObserver.observedEvents.size,
                "we triggered exactly 1 epoch change and must have observed that"
            )
            assertTrue(
                observedEvent.eventEpoch == observedEvent.conversationEpoch && observedEvent.eventEpoch == laterEpoch,
                "event epoch must equal the epoch read during the event"
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
            val alice = ccInit()
            val bob = ccInit()
            val conversationId = createConversation(bob)

            invite(bob, alice, conversationId)

            // Register observers
            bob.registerHistoryObserver(scope, bobObserver)
            alice.registerHistoryObserver(scope, aliceObserver)

            // History sharing is disabled by default
            assertFalse(bob.isHistorySharingEnabled(conversationId))

            // In another transaction, enable history sharing
            bob.transaction { ctx -> ctx.enableHistorySharing(conversationId) }

            // Before Alice received the commit, history sharing is only enabled for Bob
            assertTrue(bob.isHistorySharingEnabled(conversationId))
            assertFalse(alice.isHistorySharingEnabled(conversationId))

            val commit = MockMlsTransportSuccessProvider.getInstance().getLatestCommit()
            alice.transaction { ctx: CoreCryptoContext -> ctx.decryptMessage(conversationId, commit) }
            assertTrue(alice.isHistorySharingEnabled(conversationId))

            // Bob's observer must have observed the history secret changes, Alice's should not
            // have observed anything
            assertEquals(
                1,
                bobObserver.observedEvents.size,
                "bob triggered exactly 1 history secret changes and must have observed that"
            )
            assertEquals(
                0,
                aliceObserver.observedEvents.size,
                "alice did not trigger any history secret changes and must not have observed that"
            )
            val expected = conversationId
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
            val cc = ccInit()
            val allCredentials = cc.transaction { ctx -> ctx.getCredentials() }
            val ref = allCredentials.last()
            assertEquals(ref.type(), CredentialType.BASIC)
            assertNotEquals(ref.earliestValidity(), 0uL)
            assertThat(allCredentials).hasSize(1)
        }
    }

    @Test
    fun can_remove_basic_credential(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val cc = ccInit()
            val ref = cc.transaction { ctx ->
                ctx.`getCredentials`().last()
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
            val ciphersuite1 = CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256
            val credential1 = Credential.basic(ciphersuite1, clientId)

            val ciphersuite2 =
                CipherSuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519
            val credential2 = Credential.basic(ciphersuite2, clientId)

            val cc = ccInit(CcInitOptions.WithoutBasicCredential(clientId))
            cc.transaction { ctx ->
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
            val cc = ccInit()
            val credentialRef = cc.transaction { ctx ->
                ctx.`getCredentials`().last()
            }

            val keyPackage = cc.transaction { ctx ->
                ctx.generateKeyPackage(credentialRef)
            }

            assertNotNull(keyPackage)
        }
    }

    @Test
    fun can_serialize_keypackage(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val cc = ccInit()

            val keyPackage = generateKeyPackage(cc)

            val bytes = keyPackage.serialize()
            assertNotNull(bytes)
            assertTrue(bytes.isNotEmpty())

            // roundtrip
            val kp2 = KeyPackage(bytes)
            val bytes2 = kp2.serialize()

            assertEquals(bytes.toList(), bytes2.toList())
        }
    }

    @Test
    fun can_retrieve_keypackages_in_bulk(): TestResult {
        val scope = TestScope()
        return scope.runTest {
            val cc = ccInit()
            generateKeyPackage(cc)
            val keyPackages = cc.transaction { ctx ->
                ctx.getKeyPackages()
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
            val cc = ccInit()
            generateKeyPackage(cc)

            // add a kp which will be removed
            val keyPackage = generateKeyPackage(cc)

            // remove the keypackage
            cc.transaction { ctx ->
                ctx.removeKeyPackage(keyPackage.ref())
            }

            val keyPackages = cc.transaction { ctx ->
                ctx.getKeyPackages()
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
                CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
                clientId
            )
            val credential2 = Credential.basic(
                CipherSuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                clientId
            )

            val cc = ccInit(CcInitOptions.WithoutBasicCredential(clientId))

            cc.transaction { ctx ->
                val cref1 = ctx.addCredential(credential1)
                val cref2 = ctx.addCredential(credential2)

                val keypackagesPerCredential = 2
                for (cref in listOf(cref1, cref2)) {
                    repeat(keypackagesPerCredential) {
                        ctx.generateKeyPackage(cref)
                    }
                }

                val kpsBeforeRemoval = ctx.getKeyPackages()
                assertThat(kpsBeforeRemoval).hasSize(keypackagesPerCredential * 2)

                // remove all keypackages for one of the credentials
                ctx.removeKeyPackagesFor(cref1)

                val kps = ctx.getKeyPackages()
                assertThat(kps).hasSize(keypackagesPerCredential)
            }
        }
    }
}
