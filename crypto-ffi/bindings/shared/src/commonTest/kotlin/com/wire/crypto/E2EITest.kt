@file:Suppress("ktlint:standard:no-wildcard-imports")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import testutils.*
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test

internal class E2EITest : HasMockDeliveryService() {
    companion object {
        private val id: ConversationId = genConversationId()
    }

    @BeforeTest
    fun setup() {
        setupMocks()
    }

    @Test
    fun testSetPkiEnvironment() = runTest {
        val aliceId = genClientId()
        val root = Files.createTempDirectory("mls").toFile()
        val path = root.resolve("pki-$aliceId")
        val key = genDatabaseKey()
        val hooks = MockPkiEnvironmentHooks()
        val db = openDatabase(path.absolutePath, key)
        val pkiEnv = createPkiEnvironment(hooks, db)

        val cc = CoreCrypto(db)
        cc.setPkiEnvironment(pkiEnv)
        val pkiEnv2 = cc.getPkiEnvironment()
        assert(pkiEnv2 != null)
    }

    @Test
    fun conversation_should_be_not_verified_when_at_least_1_of_the_members_uses_a_Basic_credential() =
        runTest {
            val (alice, bob) = newClients(this@E2EITest, genClientId(), genClientId())

            bob.transaction { ctx -> ctx.createConversationShort(id) }

            val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1u).first() }
            bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome).id }

            assertThat(alice.transaction { ctx -> ctx.e2eiConversationState(groupId) }).isEqualTo(E2eiConversationState.NOT_ENABLED)
            assertThat(bob.transaction { ctx -> ctx.e2eiConversationState(groupId) }).isEqualTo(E2eiConversationState.NOT_ENABLED)
        }

    @Test
    fun e2ei_should_not_be_enabled_for_a_Basic_Credential() = runTest {
        val (alice) = newClients(this@E2EITest, genClientId())
        assertThat(alice.transaction { ctx -> ctx.e2eiIsEnabled(CIPHERSUITE_DEFAULT) }).isFalse()
    }
}
