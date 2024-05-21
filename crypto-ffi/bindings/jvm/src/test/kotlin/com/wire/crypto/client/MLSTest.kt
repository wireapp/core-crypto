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

package com.wire.crypto.client

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThat
import org.assertj.core.api.AssertionsForInterfaceTypes.assertThatNoException
import java.nio.file.Files
import kotlin.test.Test

class MLSTest {

    companion object {
        internal val id = "JfflcPtUivbg+1U3Iyrzsh5D2ui/OGS5Rvf52ipH5KY=".toGroupId()
        internal val aliceId = "alice1"
        internal val aliceId2 = "alice2"
        internal val bobId = "bob"
        internal val carolId = "carol"
    }

    @Test
    fun `externally generated ClientId should init the MLS client`() = runTest {
        val (alice, handle) = initCc().externallyGeneratedMlsClient()
        alice.mlsInitWithClientId(aliceId.toClientId(), handle)
    }

    @Test
    fun `getPublicKey should return non empty result`() = runTest {
        val (alice) = newClients(aliceId)
        assertThat(alice.getPublicKey(Ciphersuite.DEFAULT).value).isNotEmpty()
    }

    @Test
    fun `conversationExists should return true`() = runTest {
        val (alice) = newClients(aliceId)
        assertThat(alice.conversationExists(id)).isFalse()
        alice.createConversation(id)
        assertThat(alice.conversationExists(id)).isTrue()
    }

    @Test
    fun `calling generateKeyPackages should return expected number`() = runTest {
        val (alice) = newClients(aliceId)

        // by default
        assertThat(alice.validKeyPackageCount()).isEqualTo(100.toULong())

        assertThat(alice.generateKeyPackages(200U)).isNotEmpty().hasSize(200)

        assertThat(alice.validKeyPackageCount()).isEqualTo(200.toULong())
    }

    @Test
    fun `given new conversation when calling conversationEpoch should return epoch 0`() = runTest {
        val (alice) = newClients(aliceId)
        alice.createConversation(id)
        assertThat(alice.conversationEpoch(id)).isEqualTo(0UL)
    }

    @Test
    fun `updateKeyingMaterial should process the commit message`() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp)).welcome!!
        bob.commitAccepted(id)
        val welcomeBundle = alice.processWelcomeMessage(welcome)

        val commit = bob.updateKeyingMaterial(id).commit

        val decrypted = alice.decryptMessage(welcomeBundle.id, commit)
        assertThat(decrypted.message).isNull()
        assertThat(decrypted.commitDelay).isNull()
        assertThat(decrypted.senderClientId).isNull()
        assertThat(decrypted.hasEpochChanged).isTrue()
    }

    @Test
    fun `addMember should allow joining a conversation with a Welcome`() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp)).welcome!!
        val welcomeBundle = alice.processWelcomeMessage(welcome)

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(welcomeBundle.id.value).isEqualTo(id.value)
    }

    @Test
    fun `joinConversation should generate an Add proposal`() = runTest {
        val (alice1, alice2, bob) = newClients(aliceId, aliceId2, bobId)

        bob.createConversation(id)

        val alice1Kp = alice1.generateKeyPackages(1U).first()
        bob.addMember(id, listOf(alice1Kp))
        bob.commitAccepted(id)

        val proposal = alice2.joinConversation(id, 1UL, Ciphersuite.DEFAULT, CredentialType.DEFAULT)
        bob.decryptMessage(id, proposal)
        val welcome = bob.commitPendingProposals(id)?.welcome!!
        bob.commitAccepted(id)
        val welcomeBundle = alice2.processWelcomeMessage(welcome)

        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(welcomeBundle.id.value).isEqualTo(id.value)
    }

    @Test
    fun `encryptMessage should encrypt then receiver should decrypt`() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp)).welcome!!
        bob.commitAccepted(id)
        val welcomeBundle = alice.processWelcomeMessage(welcome)

        val msg = "Hello World !"
        val ciphertextMsg = alice.encryptMessage(welcomeBundle.id, msg.toPlaintextMessage())
        assertThat(ciphertextMsg).isNotEqualTo(msg)

        val plaintextMsg = bob.decryptMessage(welcomeBundle.id, ciphertextMsg).message!!
        assertThat(String(plaintextMsg)).isNotEmpty().isEqualTo(msg)
    }

    @Test
    fun `addMember should add members to the MLS group`() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        bob.createConversation(id)
        val aliceKp = alice.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp)).welcome!!
        bob.commitAccepted(id)

        alice.processWelcomeMessage(welcome)

        val carolKp = carol.generateKeyPackages(1U).first()
        val commit = bob.addMember(id, listOf(carolKp)).commit

        val decrypted = alice.decryptMessage(id, commit)
        assertThat(decrypted.message).isNull()

        assertThat(alice.members(id).containsAll(listOf(aliceId, bobId, carolId).map { it.toClientId() }))
    }

    @Test
    fun `addMember should return a valid Welcome message`() = runTest {
        val (alice, bob) = newClients(aliceId, bobId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp)).welcome!!
        bob.commitAccepted((id))

        val welcomeBundle = alice.processWelcomeMessage(welcome)
        // FIXME: simplify when https://youtrack.jetbrains.com/issue/KT-24874 fixed
        assertThat(welcomeBundle.id.value).isEqualTo(id.value)
    }

    @Test
    fun `removeMember should remove members from the MLS group`() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        bob.createConversation(id)

        val aliceKp = alice.generateKeyPackages(1U).first()
        val carolKp = carol.generateKeyPackages(1U).first()
        val welcome = bob.addMember(id, listOf(aliceKp, carolKp)).welcome!!
        bob.commitAccepted(id)
        val welcomeBundle = alice.processWelcomeMessage(welcome)

        val commit = bob.removeMember(welcomeBundle.id, listOf(carolId.toClientId())).commit

        val decrypted = alice.decryptMessage(welcomeBundle.id, commit)
        assertThat(decrypted.message).isNull()
    }

    @Test
    fun `creating proposals and removing them`() = runTest {
        val (alice, bob, carol) = newClients(aliceId, bobId, carolId)

        alice.createConversation(id)

        val bobKp = bob.generateKeyPackages(1U).first()

        // Add proposal
        alice.newAddProposal(id, bobKp)
        val welcome = alice.commitPendingProposals(id)!!.welcome!!
        alice.commitAccepted(id)

        bob.processWelcomeMessage(welcome)

        // Now creating & clearing proposal
        val carolKp = carol.generateKeyPackages(1U).first()
        val addProposal = alice.newAddProposal(id, carolKp)
        val removeProposal = alice.newRemoveProposal(id, bobId.toClientId())
        val updateProposal = alice.newUpdateProposal(id)

        val proposals = listOf(addProposal, removeProposal, updateProposal)
        proposals.forEach {
            alice.clearPendingProposal(id, it.proposalRef)
        }
        // should be null since we cleared all proposals
        assertThat(alice.commitPendingProposals(id)).isNull()
    }

    @Test
    fun `clearPendingCommit should clear the pending commit`() = runTest {
        val (alice) = newClients(aliceId)

        alice.createConversation(id)

        alice.updateKeyingMaterial(id)
        alice.clearPendingCommit(id)
        // encrypting a message would have failed if there was a pending commit
        assertThat(alice.encryptMessage(id, "Hello".toPlaintextMessage()))
    }

    @Test
    fun `wipeConversation should delete the conversation from the keystore`() = runTest {
        val (alice) = newClients(aliceId)
        alice.createConversation(id)
        assertThatNoException().isThrownBy {
            runBlocking { alice.wipeConversation(id) }
        }
    }

    @Test
    fun `deriveAvsSecret should generate a secret with the right length`() = runTest {
        val (alice) = newClients(aliceId)
        alice.createConversation(id)

        val n = 50
        val secrets = (0 until n).map {
            val secret = alice.deriveAvsSecret(id, 32U)
            assertThat(secret.value).hasSize(32)
            secret
        }.toSet()
        assertThat(secrets).hasSize(n)
    }
}

fun newClients(vararg clientIds: String) = runBlocking {
    clientIds.map { initCc().mlsClient(it.toClientId()) }
}

fun initCc(): CoreCryptoCentral = runBlocking {
    val root = Files.createTempDirectory("mls").toFile()
    val keyStore = root.resolve("keystore-${randomIdentifier()}")
    CoreCryptoCentral(keyStore.absolutePath, "secret")
}

fun randomIdentifier(n: Int = 12): String {
    val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
    return (1..n)
        .map { kotlin.random.Random.nextInt(0, charPool.size).let { charPool[it] } }
        .joinToString("")
}
