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

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.*


@OptIn(ExperimentalCoroutinesApi::class)
class MLSClientTest: BaseCoreCryptoCentralTest() {

    private suspend fun createClient(clientId: ClientId): MLSClient {
        return createCoreCryptoCentral("id${Random.nextInt()}").mlsClient(clientId)
    }

    @Test
    fun givenClient_whenCallingGetPublicKey_ReturnNonEmptyResult() = runTest {
        val mlsClient = createClient(ALICE1)
        assertTrue(mlsClient.getPublicKey().isNotEmpty())
    }

    @Test
    fun givenClient_whenCallingGenerateKeyPackages_ReturnListOfExpectedSize() = runTest {
        val mlsClient = createClient(ALICE1)
        assertTrue(mlsClient.generateKeyPackages(10).isNotEmpty())
    }

    @Test
    @Ignore // FIXME times out on JS
    fun givenNewConversation_whenCallingConversationEpoch_ReturnZeroEpoch() = runTest {
        val mlsClient = createClient(ALICE1)
        mlsClient.createConversation(MLS_CONVERSATION_ID)
        assertEquals(0UL, mlsClient.conversationEpoch(MLS_CONVERSATION_ID))
    }

    @Test
    fun givenNewConversation_whenCallingConversationEpoch_ReturnZeroEpochFoo() = runTest {
        val mlsClient = createClient(ALICE1)
        mlsClient.createConversation(MLS_CONVERSATION_ID)
        assertTrue(mlsClient.conversationExists(MLS_CONVERSATION_ID))
    }

    @Test
    fun givenTwoClients_whenCallingUpdateKeyingMaterial_weCanProcessTheCommitMessage() = runTest {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val aliceKeyPackage = aliceClient.generateKeyPackages(1).first()
        val clientKeyPackageList = listOf(Pair(ALICE1, aliceKeyPackage))
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        val commit = bobClient.updateKeyingMaterial(MLS_CONVERSATION_ID).commit
        val result = aliceClient.decryptMessage(conversationId, commit)

        assertNull(result.message)
    }

    @Test
    fun givenTwoClients_whenCallingCreateConversation_weCanProcessTheWelcomeMessage() = runTest{
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val aliceKeyPackage = aliceClient.generateKeyPackages(1).first()
        val clientKeyPackageList = listOf(Pair(ALICE1, aliceKeyPackage))
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)!!.welcome!!
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenTwoClients_whenCallingJoinConversation_weCanProcessTheAddProposalMessage() = runTest {
        val alice1Client = createClient(ALICE1)
        val alice2Client = createClient(ALICE2)
        val bobClient = createClient(BOB1)

        val alice1KeyPackage = alice1Client.generateKeyPackages(1).first()
        val clientKeyPackageList = listOf(Pair(ALICE1, alice1KeyPackage))

        bobClient.createConversation(MLS_CONVERSATION_ID)
        bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val proposal = alice2Client.joinConversation(MLS_CONVERSATION_ID, 1UL)
        bobClient.decryptMessage(MLS_CONVERSATION_ID, proposal)
        val welcome = bobClient.commitPendingProposals(MLS_CONVERSATION_ID)?.welcome
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = alice2Client.processWelcomeMessage(welcome!!)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenTwoClients_whenCallingEncryptMessage_weCanDecryptTheMessage() = runTest{
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val clientKeyPackageList = listOf(
            Pair(ALICE1, aliceClient.generateKeyPackages(1).first())
        )
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        val applicationMessage = aliceClient.encryptMessage(conversationId, PLAIN_TEXT.encodeToByteArray())
        val plainMessage = bobClient.decryptMessage(conversationId, applicationMessage).message

        assertEquals(PLAIN_TEXT, plainMessage?.decodeToString())
    }

    @Test
    fun givenTwoClients_whenCallingAddMember_weCanProcessTheWelcomeMessage() = runTest {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val clientKeyPackageList = listOf(
            Pair(ALICE1, aliceClient.generateKeyPackages(1).first())
        )
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        println("welcome: ${welcome.size}")
        bobClient.commitAccepted((MLS_CONVERSATION_ID))
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenThreeClients_whenCallingAddMember_weCanProcessTheHandshakeMessage() = runTest {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)
        val carolClient = createClient(CAROL1)

        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(
            MLS_CONVERSATION_ID,
            listOf(Pair(ALICE1, aliceClient.generateKeyPackages(1).first()))
        )?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)

        aliceClient.processWelcomeMessage(welcome)

        val commit = bobClient.addMember(
            MLS_CONVERSATION_ID,
            listOf(Pair(CAROL1, carolClient.generateKeyPackages(1).first()))
        )?.commit!!

        assertNull(aliceClient.decryptMessage(MLS_CONVERSATION_ID, commit).message)
    }

    @Test
    @Ignore // FIXME throws an error on JS
    fun givenThreeClients_whenCallingRemoveMember_weCanProcessTheHandshakeMessage() = runTest {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)
        val carolClient = createClient(CAROL1)

        val clientKeyPackageList = listOf(
            Pair(ALICE1, aliceClient.generateKeyPackages(1).first()),
            Pair(CAROL1, carolClient.generateKeyPackages(1).first())
        ).also { println(it) }
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = aliceClient.processWelcomeMessage(welcome)
        val clientRemovalList = listOf(CAROL1)
        val commit = bobClient.removeMember(conversationId, clientRemovalList).commit
        assertNull(aliceClient.decryptMessage(conversationId, commit).message)
    }

    companion object {
        const val PLAIN_TEXT = "Hello World"
        val MLS_CONVERSATION_ID = "JfflcPtUivbg+1U3Iyrzsh5D2ui/OGS5Rvf52ipH5KY=".encodeToByteArray()
        const val ALICE1 = "alice1"
        const val ALICE2 = "alice2"
        const val BOB1 = "bob1"
        const val CAROL1 = "carol1"
    }

}
