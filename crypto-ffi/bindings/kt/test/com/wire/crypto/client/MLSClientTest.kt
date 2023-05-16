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

import com.wire.crypto.CiphersuiteName
import com.wire.crypto.MlsCredentialType
import java.nio.file.Files
import kotlin.test.*
import kotlin.test.assertEquals

class MLSClientTest {

    private fun createClient(clientId: ClientId): MLSClient {
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$clientId")
        return CoreCryptoCentral(keyStore.absolutePath, "secret").mlsClient(clientId)
    }

    @Test
    fun givenClient_whenCallingGetPublicKey_ReturnNonEmptyResult() {
        val mlsClient = createClient(ALICE1)
        assertTrue(mlsClient.getPublicKey(CIPHERSUITE).isNotEmpty())
    }

    @Test
    fun givenClient_whenCallingGenerateKeyPackages_ReturnListOfExpectedSize() {
        val mlsClient = createClient(ALICE1)
        assertTrue(mlsClient.generateKeyPackages(CIPHERSUITE, 10).isNotEmpty())
    }

    @Test
    fun givenNewConversation_whenCallingConversationEpoch_ReturnZeroEpoch() {
        val mlsClient = createClient(ALICE1)
        mlsClient.createConversation(MLS_CONVERSATION_ID)
        assertEquals(0UL, mlsClient.conversationEpoch(MLS_CONVERSATION_ID))
    }

    @Test
    fun givenTwoClients_whenCallingUpdateKeyingMaterial_weCanProcessTheCommitMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val aliceKeyPackage = aliceClient.generateKeyPackages(CIPHERSUITE, 1).first()
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
    fun givenTwoClients_whenCallingCreateConversation_weCanProcessTheWelcomeMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val aliceKeyPackage = aliceClient.generateKeyPackages(CIPHERSUITE, 1).first()
        val clientKeyPackageList = listOf(Pair(ALICE1, aliceKeyPackage))
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)!!.welcome!!
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenTwoClients_whenCallingJoinConversation_weCanProcessTheAddProposalMessage() {
        val alice1Client = createClient(ALICE1)
        val alice2Client = createClient(ALICE2)
        val bobClient = createClient(BOB1)

        val alice1KeyPackage = alice1Client.generateKeyPackages(CIPHERSUITE, 1).first()
        val clientKeyPackageList = listOf(Pair(ALICE1, alice1KeyPackage))

        bobClient.createConversation(MLS_CONVERSATION_ID)
        bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val proposal = alice2Client.joinConversation(MLS_CONVERSATION_ID, 1UL, CIPHERSUITE, CREDENTIAL_TYPE)
        bobClient.decryptMessage(MLS_CONVERSATION_ID, proposal)
        val welcome = bobClient.commitPendingProposals(MLS_CONVERSATION_ID)?.welcome
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = alice2Client.processWelcomeMessage(welcome!!)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenTwoClients_whenCallingEncryptMessage_weCanDecryptTheMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val clientKeyPackageList = listOf(
            Pair(ALICE1, aliceClient.generateKeyPackages(CIPHERSUITE, 1).first())
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
    fun givenTwoClients_whenCallingAddMember_weCanProcessTheWelcomeMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)

        val clientKeyPackageList = listOf(
            Pair(ALICE1, aliceClient.generateKeyPackages(CIPHERSUITE, 1).first())
        )
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        bobClient.commitAccepted((MLS_CONVERSATION_ID))
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        assertContentEquals(MLS_CONVERSATION_ID, conversationId)
    }

    @Test
    fun givenThreeClients_whenCallingAddMember_weCanProcessTheHandshakeMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)
        val carolClient = createClient(CAROL1)

        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(
            MLS_CONVERSATION_ID,
            listOf(Pair(ALICE1, aliceClient.generateKeyPackages(CIPHERSUITE, 1).first()))
        )?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)

        aliceClient.processWelcomeMessage(welcome)

        val commit = bobClient.addMember(
            MLS_CONVERSATION_ID,
            listOf(Pair(CAROL1, carolClient.generateKeyPackages(CIPHERSUITE, 1).first()))
        )?.commit!!

        assertNull(aliceClient.decryptMessage(MLS_CONVERSATION_ID, commit).message)
    }

    @Test
    fun givenThreeClients_whenCallingRemoveMember_weCanProcessTheHandshakeMessage() {
        val aliceClient = createClient(ALICE1)
        val bobClient = createClient(BOB1)
        val carolClient = createClient(CAROL1)

        val clientKeyPackageList = listOf(
            ALICE1 to aliceClient.generateKeyPackages(CIPHERSUITE, 1).first(),
            CAROL1 to carolClient.generateKeyPackages(CIPHERSUITE, 1).first()
        )
        bobClient.createConversation(MLS_CONVERSATION_ID)
        val welcome = bobClient.addMember(MLS_CONVERSATION_ID, clientKeyPackageList)?.welcome!!
        bobClient.commitAccepted(MLS_CONVERSATION_ID)
        val conversationId = aliceClient.processWelcomeMessage(welcome)

        val clientRemovalList = listOf(CAROL1)
        val commit = bobClient.removeMember(conversationId, clientRemovalList).commit

        assertNull(aliceClient.decryptMessage(conversationId, commit).message)
    }

    @Test
    fun e2ei() {
        val clientId = ALICE1
        val root = Files.createTempDirectory("mls").toFile()
        val keyStore = root.resolve("keystore-$clientId")
        val cc = CoreCryptoCentral(keyStore.absolutePath, "secret")
        val enrollment = cc.e2eiNewEnrollment(
            clientId = "NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg:6c1866f567616f31@wire.com",
            displayName = "Alice Smith",
            handle = "alice_wire",
            expiryDays = 90u,
            ciphersuite = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519
        )
        val directoryResponse = """{
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order"
        }""".trimIndent().toByteArray()
        enrollment.directoryResponse(directoryResponse)

        val previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM"
        enrollment.newAccountRequest(previousNonce)

        val accountResponse = """{
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        }""".trimIndent().toByteArray()
        enrollment.accountResponse(accountResponse)

        enrollment.newOrderRequest(previousNonce)
        val orderResponse = """{
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
            ],
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }""".trimIndent().toByteArray()
        val newOrder = enrollment.newOrderResponse(orderResponse)

        val orderUrl = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth"
        val authzUrl = newOrder.authorizations[0]
        enrollment.newAuthzRequest(authzUrl, previousNonce)
        val authzResponse = """{
            "status": "pending",
            "expires": "2016-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            },
            "challenges": [
              {
                "type": "wire-oidc-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://dex/dex"
              },
              {
                "type": "wire-dpop-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://wire.com/clients/6c1866f567616f31/access-token"
              }
            ]
        }""".toByteArray()
        enrollment.authzResponse(authzResponse)

        val backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU"
        enrollment.createDpopToken(backendNonce)
        val accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA"
        enrollment.newDpopChallengeRequest(accessToken, previousNonce)
        val dpopChallengeResponse = """{
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        }""".toByteArray()
        enrollment.challengeResponse(dpopChallengeResponse)

        enrollment.checkOrderRequest(orderUrl, previousNonce)
        val checkOrderResponse = """{
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }""".toByteArray()
        enrollment.checkOrderResponse(checkOrderResponse)

        enrollment.finalizeRequest(previousNonce)
        val finalizeResponse = """{
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        }""".toByteArray()
        enrollment.finalizeResponse(finalizeResponse)

        enrollment.certificateRequest(previousNonce)
        val certificateChain = """-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQIi6jHWSEF/LHAkiyoiSHbjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA0MDUwOTI2NThaFw0yMzA0MDUxMDI2NThaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabE
AtDJIefbX1/wDUSDJbEL/nJNo4IBBjCCAQIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUhifYTPG7M3pyQMrz
HYmakvfDG80wHwYDVR0jBBgwFoAUHPSH1n7X87LAYJnc+cFG2a3ZAQ4wcgYDVR0R
BGswaYZQaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRB
Mk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb22GFWltOndpcmVh
cHA9YWxpY2Vfd2lyZTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYI
KoZIzj0EAwIDSAAwRQIhAKY0Zs8SYwS7mFFenPDoCDHPQbCbV9VdvYpBQncOFD5K
AiAisX68Di4B0dN059YsVDXpM0drnkrVTRKHV+F+ipDjZQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQPbElEJQ58HlbQf7bqrJjXTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDA1MDky
NjUzWhcNMzMwNDAyMDkyNjUzWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbM
rA1eqJE9xlGOwO+sYbexThtlU/to9jJj5SBoKPx7Q8QMBlmPTjqDVumXhUvSe+xY
JE7M+lBXfVZCywzIIPWjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQc9IfWftfzssBgmdz5wUbZrdkBDjAfBgNVHSMEGDAW
gBQY+1rDw64QLm/weFQC1mo9y29ddTAKBggqhkjOPQQDAgNHADBEAiARvd7RBuuv
OhUy7ncjd/nzoN5Qs0p6D+ujdSLDqLlNIAIgfkwAAgsQMDF3ClqVM/p9cmS95B0g
CAdIObqPoNL5MJo=
-----END CERTIFICATE-----""".trimIndent()
         cc.e2eiMlsClient(enrollment, certificateChain)
    }

    companion object {
        val CIPHERSUITE = CiphersuiteName.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519
        val CREDENTIAL_TYPE = MlsCredentialType.BASIC
        const val PLAIN_TEXT = "Hello World"
        val MLS_CONVERSATION_ID = "JfflcPtUivbg+1U3Iyrzsh5D2ui/OGS5Rvf52ipH5KY=".encodeToByteArray()
        val ALICE1 = "alice1"
        val ALICE2 = "alice2"
        val BOB1 = "bob1"
        val CAROL1 = "carol1"
    }
}
