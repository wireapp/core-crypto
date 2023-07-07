@file:Suppress("INTERFACE_WITH_SUPERCLASS", "OVERRIDING_FINAL_MEMBER", "RETURN_TYPE_MISMATCH_ON_OVERRIDE", "CONFLICTING_OVERLOADS")
@file:JsModule("@wireapp/core-crypto")
@file:JsNonModule
package externals

import kotlin.js.*
import org.khronos.webgl.*
import org.w3c.dom.*
import org.w3c.dom.events.*
import org.w3c.dom.parsing.*
import org.w3c.dom.svg.*
import org.w3c.dom.url.*
import org.w3c.fetch.*
import org.w3c.files.*
import org.w3c.notifications.*
import org.w3c.performance.*
import org.w3c.workers.*
import org.w3c.xhr.*
import tsstdlib.Map

//typealias CoreCryptoError = Error

external enum class Ciphersuite {
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 /* = 1 */,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 /* = 2 */,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 /* = 3 */,
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 /* = 4 */,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 /* = 5 */,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 /* = 6 */,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 /* = 7 */
}

external enum class CredentialType {
    Basic /* = 1 */,
    X509 /* = 2 */
}

external interface ConversationConfiguration {
    var ciphersuite: Ciphersuite?
        get() = definedExternally
        set(value) = definedExternally
    var externalSenders: Array<Uint8Array>?
        get() = definedExternally
        set(value) = definedExternally
    var custom: CustomConfiguration?
        get() = definedExternally
        set(value) = definedExternally
}

external enum class WirePolicy {
    Plaintext /* = 1 */,
    Ciphertext /* = 2 */
}

external interface CustomConfiguration {
    var keyRotationSpan: Number?
        get() = definedExternally
        set(value) = definedExternally
    var wirePolicy: WirePolicy?
        get() = definedExternally
        set(value) = definedExternally
}

//typealias ConversationId = Uint8Array

//typealias ClientId = Uint8Array

//typealias ProposalRef = Uint8Array

external interface ProteusAutoPrekeyBundle {
    var id: Number
    var pkb: Uint8Array
}

external interface MemberAddedMessages {
    var commit: Uint8Array
    var welcome: Uint8Array
    var groupInfo: GroupInfoBundle
}

external interface CommitBundle {
    var commit: Uint8Array
    var welcome: Uint8Array?
        get() = definedExternally
        set(value) = definedExternally
    var groupInfo: GroupInfoBundle
}

external interface GroupInfoBundle {
    var encryptionType: GroupInfoEncryptionType
    var ratchetTreeType: RatchetTreeType
    var payload: Uint8Array
}

external enum class GroupInfoEncryptionType {
    Plaintext /* = 1 */,
    JweEncrypted /* = 2 */
}

external enum class RatchetTreeType {
    Full /* = 1 */,
    Delta /* = 2 */,
    ByRef /* = 3 */
}

external interface CoreCryptoDeferredParams {
    var databaseName: String
    var key: String
    var ciphersuites: Array<Ciphersuite>
    var entropySeed: Uint8Array?
        get() = definedExternally
        set(value) = definedExternally
    var wasmFilePath: String?
        get() = definedExternally
        set(value) = definedExternally
}

external interface CoreCryptoParams : CoreCryptoDeferredParams {
    var clientId: Uint8Array
}

external interface Invitee {
    var id: Uint8Array
    var kp: Uint8Array
}

external interface ConversationInitBundle {
    var conversationId: Uint8Array
    var commit: Uint8Array
    var groupInfo: GroupInfoBundle
}

external interface DecryptedMessage {
    var message: Uint8Array?
        get() = definedExternally
        set(value) = definedExternally
    var proposals: Array<ProposalBundle>
    var isActive: Boolean
    var commitDelay: Number?
        get() = definedExternally
        set(value) = definedExternally
    var senderClientId: Uint8Array?
        get() = definedExternally
        set(value) = definedExternally
    var hasEpochChanged: Boolean
    var identity: WireIdentity?
        get() = definedExternally
        set(value) = definedExternally
}

external interface WireIdentity {
    var clientId: String
    var handle: String
    var displayName: String
    var domain: String
}

external interface ProposalBundle {
    var proposal: Uint8Array
    var proposalRef: Uint8Array
}

external enum class ProposalType {
    Add /* = 0 */,
    Remove /* = 1 */,
    Update /* = 2 */
}

external interface ProposalArgs {
    var conversationId: Uint8Array
}

external interface AddProposalArgs : ProposalArgs {
    var kp: Uint8Array
}

external interface RemoveProposalArgs : ProposalArgs {
    var clientId: Uint8Array
}

external enum class ExternalProposalType {
    Add /* = 0 */
}

external interface ExternalProposalArgs {
    var conversationId: Uint8Array
    var epoch: Number
}

external interface ExternalAddProposalArgs : ExternalProposalArgs {
    var ciphersuite: Ciphersuite
    var credentialType: CredentialType
}

external interface CoreCryptoCallbacks {
    var authorize: (conversationId: Uint8Array, clientId: Uint8Array) -> Promise<Boolean>
    var userAuthorize: (conversationId: Uint8Array, externalClientId: Uint8Array, existingClients: Array<Uint8Array>) -> Promise<Boolean>
    var clientIsExistingGroupUser: (conversationId: Uint8Array, clientId: Uint8Array, existingClients: Array<Uint8Array>, parent_conversation_clients: Array<Uint8Array>) -> Promise<Boolean>
}

external open class CoreCrypto {
    open fun mlsInit(clientId: Uint8Array, ciphersuites: Array<Ciphersuite>): Promise<Unit>
    open fun mlsGenerateKeypair(ciphersuites: Array<Ciphersuite>): Promise<Array<Uint8Array>>
    open fun mlsInitWithClientId(clientId: Uint8Array, signaturePublicKeys: Array<Uint8Array>, ciphersuites: Array<Ciphersuite>): Promise<Unit>
    open fun isLocked(): Boolean
    open fun wipe(): Promise<Unit>
    open fun close(): Promise<Unit>
    open fun registerCallbacks(callbacks: CoreCryptoCallbacks, ctx: Any = definedExternally): Promise<Unit>
    open fun conversationExists(conversationId: Uint8Array): Promise<Boolean>
    open fun markConversationAsChildOf(childId: Uint8Array, parentId: Uint8Array): Promise<Unit>
    open fun conversationEpoch(conversationId: Uint8Array): Promise<Number>
    open fun wipeConversation(conversationId: Uint8Array): Promise<Unit>
    open fun createConversation(conversationId: Uint8Array, creatorCredentialType: CredentialType, configuration: ConversationConfiguration = definedExternally): Promise<Any>
    open fun decryptMessage(conversationId: Uint8Array, payload: Uint8Array): Promise<DecryptedMessage>
    open fun encryptMessage(conversationId: Uint8Array, message: Uint8Array): Promise<Uint8Array>
    open fun processWelcomeMessage(welcomeMessage: Uint8Array, configuration: CustomConfiguration = definedExternally): Promise<Uint8Array>
    open fun clientPublicKey(ciphersuite: Ciphersuite): Promise<Uint8Array>
    open fun clientValidKeypackagesCount(ciphersuite: Ciphersuite): Promise<Number>
    open fun clientKeypackages(ciphersuite: Ciphersuite, amountRequested: Number): Promise<Array<Uint8Array>>
    open fun addClientsToConversation(conversationId: Uint8Array, clients: Array<Invitee>): Promise<MemberAddedMessages>
    open fun removeClientsFromConversation(conversationId: Uint8Array, clientIds: Array<Uint8Array>): Promise<CommitBundle>
    open fun updateKeyingMaterial(conversationId: Uint8Array): Promise<CommitBundle>
    open fun commitPendingProposals(conversationId: Uint8Array): Promise<CommitBundle?>
    open fun newProposal(proposalType: ProposalType, args: ProposalArgs): Promise<ProposalBundle>
    open fun newProposal(proposalType: ProposalType, args: AddProposalArgs): Promise<ProposalBundle>
    open fun newProposal(proposalType: ProposalType, args: RemoveProposalArgs): Promise<ProposalBundle>
    open fun newExternalProposal(externalProposalType: ExternalProposalType, args: ExternalAddProposalArgs): Promise<Uint8Array>
    open fun exportGroupInfo(conversationId: Uint8Array): Promise<Uint8Array>
    open fun joinByExternalCommit(groupInfo: Uint8Array, credentialType: CredentialType, configuration: CustomConfiguration = definedExternally): Promise<ConversationInitBundle>
    open fun mergePendingGroupFromExternalCommit(conversationId: Uint8Array): Promise<Unit>
    open fun clearPendingGroupFromExternalCommit(conversationId: Uint8Array): Promise<Unit>
    open fun commitAccepted(conversationId: Uint8Array): Promise<Unit>
    open fun clearPendingProposal(conversationId: Uint8Array, proposalRef: Uint8Array): Promise<Unit>
    open fun clearPendingCommit(conversationId: Uint8Array): Promise<Unit>
    open fun exportSecretKey(conversationId: Uint8Array, keyLength: Number): Promise<Uint8Array>
    open fun getClientIds(conversationId: Uint8Array): Promise<Array<Uint8Array>>
    open fun randomBytes(length: Number): Promise<Uint8Array>
    open fun reseedRng(seed: Uint8Array): Promise<Unit>
    open fun proteusInit(): Promise<Unit>
    open fun proteusSessionFromPrekey(sessionId: String, prekey: Uint8Array): Promise<Unit>
    open fun proteusSessionFromMessage(sessionId: String, envelope: Uint8Array): Promise<Uint8Array>
    open fun proteusSessionSave(sessionId: String): Promise<Unit>
    open fun proteusSessionDelete(sessionId: String): Promise<Unit>
    open fun proteusSessionExists(sessionId: String): Promise<Boolean>
    open fun proteusDecrypt(sessionId: String, ciphertext: Uint8Array): Promise<Uint8Array>
    open fun proteusEncrypt(sessionId: String, plaintext: Uint8Array): Promise<Uint8Array>
    open fun proteusEncryptBatched(sessions: Array<String>, plaintext: Uint8Array): Promise<Map<String, Uint8Array>>
    open fun proteusNewPrekey(prekeyId: Number): Promise<Uint8Array>
    open fun proteusNewPrekeyAuto(): Promise<ProteusAutoPrekeyBundle>
    open fun proteusLastResortPrekey(): Promise<Uint8Array>
    open fun proteusFingerprint(): Promise<String>
    open fun proteusFingerprintLocal(sessionId: String): Promise<String>
    open fun proteusFingerprintRemote(sessionId: String): Promise<String>
    open fun proteusCryptoboxMigrate(storeName: String): Promise<Unit>
    open fun proteusLastErrorCode(): Promise<Number>
    open fun e2eiNewEnrollment(clientId: String, displayName: String, handle: String, expiryDays: Number, ciphersuite: Ciphersuite): Promise<WireE2eIdentity>
    open fun e2eiMlsInit(enrollment: WireE2eIdentity, certificateChain: String): Promise<Unit>
    open fun e2eiEnrollmentStash(enrollment: WireE2eIdentity): Promise<Uint8Array>
    open fun e2eiEnrollmentStashPop(handle: Uint8Array): Promise<WireE2eIdentity>
    open fun e2eiIsDegraded(conversationId: Uint8Array): Promise<Boolean>

    companion object {
        fun init(__0: CoreCryptoParams): Promise<CoreCrypto>
        fun deferredInit(__0: CoreCryptoDeferredParams): Promise<CoreCrypto>
        fun proteusLastResortPrekeyId(): Number
        fun proteusFingerprintPrekeybundle(prekey: Uint8Array): String
        fun version(): String
    }
}

//typealias JsonRawData = Uint8Array

external open class WireE2eIdentity(e2ei: Any) {
    open fun free()
    open fun inner(): Any
    open fun directoryResponse(directory: Uint8Array): AcmeDirectory
    open fun newAccountRequest(previousNonce: String): Uint8Array
    open fun newAccountResponse(account: Uint8Array)
    open fun newOrderRequest(previousNonce: String): Uint8Array
    open fun newOrderResponse(order: Uint8Array): NewAcmeOrder
    open fun newAuthzRequest(url: String, previousNonce: String): Uint8Array
    open fun newAuthzResponse(authz: Uint8Array): NewAcmeAuthz
    open fun createDpopToken(expirySecs: Number, backendNonce: String): Uint8Array
    open fun newDpopChallengeRequest(accessToken: String, previousNonce: String): Uint8Array
    open fun newOidcChallengeRequest(idToken: String, previousNonce: String): Uint8Array
    open fun newChallengeResponse(challenge: Uint8Array)
    open fun checkOrderRequest(orderUrl: String, previousNonce: String): Uint8Array
    open fun checkOrderResponse(order: Uint8Array): String
    open fun finalizeRequest(previousNonce: String): Uint8Array
    open fun finalizeResponse(finalize: Uint8Array): String
    open fun certificateRequest(previousNonce: String): Uint8Array
}

external interface AcmeDirectory {
    var newNonce: String
    var newAccount: String
    var newOrder: String
}

external interface NewAcmeOrder {
    var delegate: Uint8Array
    var authorizations: Array<Uint8Array>
}

external interface NewAcmeAuthz {
    var identifier: String
    var wireDpopChallenge: AcmeChallenge?
        get() = definedExternally
        set(value) = definedExternally
    var wireOidcChallenge: AcmeChallenge?
        get() = definedExternally
        set(value) = definedExternally
}

external interface AcmeChallenge {
    var delegate: Uint8Array
    var url: String
    var target: String
}
