@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

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
        val db = Database.open(path.absolutePath, key)
        val pkiEnv = PkiEnvironment.new(hooks, db)

        val cc = CoreCrypto(db)
        cc.setPkiEnvironment(pkiEnv)
        val pkiEnv2 = cc.getPkiEnvironment()
        assert(pkiEnv2 != null)
    }

    @Test
    fun testInstantiateX509CredentialAcquisition() = runTest {
        val root = Files.createTempDirectory("mls").toFile()
        val path = root.resolve("pki-acquisition")
        val key = genDatabaseKey()
        val hooks = MockPkiEnvironmentHooks()
        val db = Database.open(path.absolutePath, key)
        val pkiEnv = PkiEnvironment.new(hooks, db)
        val clientId =
            ClientId("LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com".encodeToByteArray())

        val acquisition = X509CredentialAcquisition(
            pkiEnv,
            X509CredentialAcquisitionConfiguration(
                acmeUrl = "acme.example.com",
                idpUrl = "https://idp.example.com",
                ciphersuite = CIPHERSUITE_DEFAULT,
                displayName = "Alice Smith",
                clientId = clientId,
                handle = "alice_wire",
                domain = "world.com",
                team = null,
                validityPeriodSecs = 3600uL
            )
        )

        assertThat(acquisition).isNotNull
    }

    @Test
    fun conversation_should_be_not_verified_when_at_least_1_of_the_members_uses_a_Basic_credential() =
        runTest {
            val (alice, bob) = newClients(genClientId(), genClientId())

            bob.transaction { ctx -> ctx.createConversationShort(id) }

            val aliceKp = alice.transaction { ctx -> ctx.clientKeypackagesShort(1u).first() }
            bob.transaction { ctx -> ctx.addClientsToConversation(id, listOf(aliceKp)) }
            val welcome = mockDeliveryService.getLatestWelcome()
            val groupId = alice.transaction { ctx -> ctx.processWelcomeMessage(welcome) }

            assertThat(alice.transaction { ctx -> ctx.e2eiConversationState(groupId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
            assertThat(bob.transaction { ctx -> ctx.e2eiConversationState(groupId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
        }

    @Test
    fun e2ei_should_not_be_enabled_for_a_Basic_Credential() = runTest {
        val (alice) = newClients(genClientId())
        assertThat(alice.transaction { ctx -> ctx.e2eiIsEnabled(CIPHERSUITE_DEFAULT) }).isFalse()
    }
}
