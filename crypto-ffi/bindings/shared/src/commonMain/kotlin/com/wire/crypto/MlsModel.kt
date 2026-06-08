package com.wire.crypto

/** The default cipher suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519` */
val CIPHERSUITE_DEFAULT = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519

/** The default set of cipher suites: `[MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519]` */
val CIPHERSUITES_DEFAULT: List<CipherSuite> = listOf(CIPHERSUITE_DEFAULT)

/** Default credential type */
val CREDENTIAL_TYPE_DEFAULT = CredentialType.BASIC

/** Construct a client ID */
fun String.toClientId() = ClientId(this.toByteArray())

/** Construct a Welcome */
fun ByteArray.toWelcome() = Welcome(this)

/** Construct a KeyPackage from bytes */
fun ByteArray.toMLSKeyPackage() = KeyPackage(this)

/** Construct an AVS secret */
fun ByteArray.toAvsSecret() = SecretKey(this)

/** Construct a GroupInfo from bytes */
fun ByteArray.toGroupInfo() = GroupInfo(this)

/** Initialise or open a Database */
suspend fun Database.Companion.open(
    location: String,
    key: DatabaseKey
) = openDatabase(location, key)

/** Initialise an in-memory Database whose data will be lost when the instance is dropped */
suspend fun Database.Companion.open(
    key: DatabaseKey
) = inMemoryDatabase(key)

/** Create a new PKI environment */
suspend fun PkiEnvironment.Companion.new(
    hooks: PkiEnvironmentHooks,
    database: Database
) = createPkiEnvironment(hooks, database)

/**
 * Create a new credential acquisition from an existing credential.
 * This API is temporary until our system decouples client identities from a client's public signature key.
 * See [https://wearezeta.atlassian.net/wiki/x/RABtrQ](https://wearezeta.atlassian.net/wiki/x/RABtrQ).
 *
 * Provide [coreCryptoDatabase] if you're using distinct DB instances for [PkiEnvironment] and [CoreCrypto].
 * Otherwise, the [PkiEnvironment]'s DB will be used to load the full credential.
 */
suspend fun X509CredentialAcquisition.Companion.newFromCredentialRef(
    pkiEnvironment: PkiEnvironment,
    config: X509CredentialAcquisitionConfiguration,
    credentialRef: CredentialRef,
    coreCryptoDatabase: Database? = null,
) = x509CredentialAcquisitionNewFromCredentialRef(pkiEnvironment, config, credentialRef, coreCryptoDatabase)
