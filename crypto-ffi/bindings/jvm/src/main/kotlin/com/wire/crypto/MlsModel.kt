package com.wire.crypto

/** The default ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519` */
val CIPHERSUITE_DEFAULT = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519
/** The default set of ciphersuites: `[MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519]` */
val CIPHERSUITES_DEFAULT: List<Ciphersuite> = listOf(CIPHERSUITE_DEFAULT)

/** Default credential type */
val CREDENTIAL_TYPE_DEFAULT = CredentialType.BASIC

/** Default Custom Configuration */
val CUSTOM_CONFIGURATION_DEFAULT = CustomConfiguration(null, null)

/** Default Conversation Configuration */
val CONVERSATION_CONFIGURATION_DEFAULT = ConversationConfiguration(null, listOf(), CUSTOM_CONFIGURATION_DEFAULT)

/** Construct a client ID */
fun String.toClientId() = ClientId(this.toByteArray())
