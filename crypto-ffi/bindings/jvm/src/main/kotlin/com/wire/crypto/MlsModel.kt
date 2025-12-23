package com.wire.crypto

/** The default ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519` */
val CIPHERSUITE_DEFAULT = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519

/** The default set of ciphersuites: `[MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519]` */
val CIPHERSUITES_DEFAULT: List<Ciphersuite> = listOf(CIPHERSUITE_DEFAULT)

/** Default credential type */
val CREDENTIAL_TYPE_DEFAULT = CredentialType.BASIC

/** Construct a client ID */
fun String.toClientId() = ClientId(this.toByteArray())

/** Construct an external sender ID */
fun ByteArray.toExternalSenderKey() = ExternalSenderKey(this)

/** Construct a Welcome */
fun ByteArray.toWelcome() = Welcome(this)

/** Construct a KeyPackage from bytes */
fun ByteArray.toMLSKeyPackage() = Keypackage(this)

/** Construct an AVS secret */
fun ByteArray.toAvsSecret() = SecretKey(this)

/** Construct a GroupInfo from bytes */
fun ByteArray.toGroupInfo() = GroupInfo(this)

/** Construct a new Credential from ciphersuite and client id */
@Throws(CoreCryptoException::class)
fun Credential.Companion.basic(
    ciphersuite: Ciphersuite,
    clientId: ClientId
): Credential = credentialBasic(ciphersuite, clientId)
