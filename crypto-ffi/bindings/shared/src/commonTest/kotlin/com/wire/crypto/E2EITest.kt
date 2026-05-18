@file:Suppress("ktlint:standard:no-wildcard-imports", "WildcardImport")

package com.wire.crypto

import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import testutils.*
import java.nio.file.Files
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test

internal class E2EITest {
    @Test
    fun testSetPkiEnvironment() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
        val pkiEnv = PkiEnvironment.new(hooks, db)

        val cc = CoreCrypto(db)
        cc.setPkiEnvironment(pkiEnv)
        val pkiEnv2 = cc.getPkiEnvironment()
        assert(pkiEnv2 != null)
    }

    @Test
    fun testInstantiateX509CredentialAcquisition() = runTest {
        val hooks = MockPkiEnvironmentHooks()
        val db = newDatabase()
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
            val alice = ccInit()
            val bob = ccInit()

            val conversationId = createConversation(bob)
            invite(bob, alice, conversationId)
            assertThat(alice.transaction { ctx -> ctx.e2eiConversationState(conversationId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
            assertThat(bob.transaction { ctx -> ctx.e2eiConversationState(conversationId) })
                .isEqualTo(E2eiConversationState.NOT_ENABLED)
        }

    @Test
    fun e2ei_should_not_be_enabled_for_a_Basic_Credential() = runTest {
        val alice = ccInit()
        assertThat(alice.transaction { ctx -> ctx.e2eiIsEnabled(CIPHERSUITE_DEFAULT) }).isFalse()
    }
}
