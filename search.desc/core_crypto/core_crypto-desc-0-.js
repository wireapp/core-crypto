searchState.loadedDescShard("core_crypto", 0, "Core Crypto is a wrapper on top of OpenMLS aimed to …\nThe message was rejected by the delivery service and there…\nMetadata describing the conditions of the build of this …\nMetadata describing the conditions of the build of this …\nThis error is emitted when the requested conversation …\nThis error is emitted when the requested conversation …\nWrapper superstruct for both mls::MlsCentral and …\nA cryptobox migration operation failed\nWrapper for errors that can happen during a Cryptobox …\nWrap a crate::e2e_identity::Error for recursion.\nWhen looking for a X509 credential for a given ciphersuite …\nContains the error value\nErrors produced by the root module group\nAny error that occurs during mls transport.\nThis item requires a feature that the core-crypto library …\nOpenMLS GroupInfo error\nError when inspecting a Cryptobox store that doesn’t …\nProduce the error message from the innermost wrapped error.\nThe MLS group is in an invalid state for an unknown reason\nInvalid Context. This context has been finished and can no …\nA key store operation failed\nA key store operation failed\nCommon errors we generate\nThese errors can be raised from several different modules, …\nUnexpectedly failed to retrieve group info\nError when trying to fetch a certain key from a structured …\nWrap a crate::mls::Error for recursion.\nAn external MLS operation failed\nAdd members error\nWrap a crate::mls::client::Error for recursion.\nCommit to pending proposals error\nWrap a crate::mls::conversation::Error for recursion.\nWrap a crate::mls::credential::Error for recursion.\nAn error that occurs in methods of a …\nOpenMls crypto error\nOpenMLS delete KeyPackage error\nEmptyInput error\nOpenMLS encrypt message error\nA MLS operation failed, but we captured some context about …\nOpenmls produces these kinds of error\nA wrapper struct for an error string. This can be used …\nExport public group state error\nOpenMls Export Secret error\nExternal Commit error\nCreate message error\n<code>KeyPackageBundle</code> new error\nOpenMLS keypackage validation error\nThis type represents all possible errors that can occur …\nOpenMLS LeafNode validation error\nGeneric error type that indicates unrecoverable errors in …\nOpenMLS merge commit error\nOpenMLS Commit merge error\nParse message error\nGroup state error\nNew group error\nRemove members error\nSelf update error\nErrors that are thrown by TLS serialization crate.\nClient callbacks to allow communication with the delivery …\nMls Transport Callbacks were not provided\nResponse from the delivery service\nOpenMLS update extensions error\nWelcome error\nContains the success value\nPropose add members error\nPropose remove members error\nPropose self update error\nA Proteus operation failed\nError when decoding CBOR and/or decrypting Proteus messages\nError when encoding CBOR and/or decrypting Proteus messages\nA Proteus operation failed, but we captured some context …\nProteus produces these kinds of error\nVarious internal Proteus errors\nThe proteus client has been called but has not been …\nError when there’s a critical error within a proteus …\nError when trying to open a Cryptobox store that doesn’t …\nProvider Error\nOpenMLS LeafNode validation error\nA crate-internal operation failed\nThese errors wrap each of the module-specific errors in …\nA module-specific Result type with a default error variant.\nA client should have consumed all incoming messages before …\nWrap a crate::Error for recursion.\nThe message was accepted by the delivery service\nLike <code>Into</code>, but different, because we don’t actually want …\nError when trying to coerce a certain value to a certain …\nWhether this build was in Debug mode (true) or Release …\nFeatures enabled for this build\nConstruct a recursive error given the current context\nThis module contains the primitives to enable …\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nre-export rusty-jwt-tools API\nConvert a crate::e2e_identity::Error into a RecursiveError…\nReturns the proteus error code\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGit branch\nOutput of <code>git describe</code>\n<code>true</code> when the source code differed from the commit at the …\nHash of current git commit\nProduce the error message from the innermost wrapped error.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nMLS Abstraction\nConvert a crate::mls::Error into a RecursiveError, with …\nConvert a crate::mls::client::Error into a RecursiveError, …\nConvert a crate::mls::conversation::Error into a …\nConvert a crate::mls::credential::Error into a …\nCreates a new transaction. All operations that persist …\nOptimization level\nCommon imports that should be useful for most uses of the …\nProteus Abstraction\nReturns the proteus identity’s public key fingerprint\nReturns the proteus identity’s public key fingerprint\nReturns the proteus identity’s public key fingerprint\nReturns the proteus last resort prekey id (u16::MAX = …\nProteus session accessor\nProteus session exists\nConvert a crate::Error into a RecursiveError, with context\nSend a commit bundle to the corresponding endpoint.\nSend a message to the corresponding endpoint.\nWhat happened\nWhat happened\nWhat happened\nWhat happened with the keystore\nAllows to extract the MLS Client from the wrapper …\nBuild target triple\nBuild Timestamp\nWhy did the delivery service reject the message?\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nThis struct provides transactional support for Core Crypto.\nAborts the transaction, meaning it discards all the …\nsee MlsCentral::client_id\nsee MlsCentral::client_public_key\nReturns the count of valid, non-expired, unclaimed …\nChecks if a given conversation id exists locally\nAcquire a conversation guard.\nPrunes local KeyPackages after making sure they also have …\nDeletes all key packages whose leaf node’s credential …\nSee MlsCentral::e2ei_dump_pki_env.\nAllows persisting an active enrollment (for example while …\nFetches the persisted enrollment and deletes it from the …\nSee MlsCentral::e2ei_is_enabled\nSee MlsCentral::e2ei_is_pki_env_setup. Unlike …\nParses the ACME server response from the endpoint fetching …\nGenerates an E2EI enrollment instance for a “regular” …\nCreates an enrollment instance with private key material …\nGenerates an E2EI enrollment instance for a E2EI client …\nRegisters a Root Trust Anchor CA for the use in E2EI …\nRegisters a CRL for the use in E2EI processing.\nRegisters an Intermediate CA for the use in E2EI …\nSee MlsCentral::e2ei_verify_group_state.\nCommits the transaction, meaning it takes all the enqueued …\nReturns the argument unchanged.\nSee MlsCentral::get_credential_in_use.\nGet the data that has previously been set by …\nReturns <code>amount_requested</code> OpenMLS …\nCalls <code>U::from(self)</code>.\nIssues an external commit and stores the group in a …\nGenerates MLS KeyPairs/CredentialBundle with a temporary, …\nInitializes the MLS client if super::CoreCrypto has …\nUpdates the current temporary Client ID with the newly …\nClones all references that the MlsCryptoProvider comprises.\nCreates a new Add proposal\nCreate a new empty conversation\nCrafts a new external Add proposal. Enables a client …\nCreates a new Add proposal\nCreates a new Add proposal\nCreate a conversation from a TLS serialized MLS Welcome …\nCreate a conversation from a received MLS Welcome message\nMigrates an existing Cryptobox data store (whether a …\nDecrypts a proteus message envelope\nEncrypts proteus message for a given session ID\nEncrypts a proteus message for several sessions ID. This …\nReturns the proteus identity’s public key fingerprint\nReturns the proteus identity’s public key fingerprint\nReturns the proteus identity’s public key fingerprint\nInitializes the proteus client\nReturns the last resort prekey\nReturns the proteus last resort prekey id (u16::MAX = …\nCreates a new Proteus prekey and returns the …\nCreates a new Proteus prekey with an automatically …\nReloads the sessions from the key store\nProteus session accessor\nDeletes a proteus session from the keystore\nProteus session exists\nCreates a proteus session from a Proteus message envelope\nCreates a proteus session from a prekey\nSaves a proteus session in the keystore\nGenerates a random byte array of the specified size\nSaves a new X509 credential. Requires first having …\nSet arbitrary data to be retrieved by …\nParses supplied key from Delivery Service in order to …\nDestroys a group locally\nSupporting struct for CRL registration result\nDump of the PKI environemnt as PEM\nWire end to end identity solution for fetching a x509 …\nContains the error value\nContains the success value\nCreates a request for finally fetching the x509 …\nVerifies that the previous challenge has been completed.\nParses the response from …\nGenerates a new client Dpop JWT token. It demonstrates …\nCRLs registered in the PKI env\nParses the response from …\nWhether this CRL modifies the old CRL (i.e. has a …\nUtility for clients to get the current state of E2EI when …\nOptional expiration timestamp\nFinal step before fetching the certificate.\nParses the response from …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nLets clients retrieve the OIDC refresh token to try to …\nIntermediate CAs that are loaded\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nFor creating a new acme account. This returns a signed …\nParses the response from …\nCreates a new authorization request.\nParses the response from …\nCreates a new challenge request.\nParses the response from …\nCreates a new challenge request.\nParses the response from …\nCreates a new acme order for the handle (userId + display …\nParses the response from …\nRoot CA in use (i.e. Trust Anchor)\nBuilds an instance holding private key material. This …\nWe only expose byte arrays through the FFI so we do all …\nFor creating a challenge see RFC 8555 Section 7.5.1\nSee RFC 8555 Section 7.1.1\nResult of an authorization creation see RFC 8555 Section …\nResult of an order creation see RFC 8555 Section 7.4\nAuthorizations to create with …\nACME Challenge\nOpaque raw json value\nOpaque raw json value\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nDNS entry associated with those challenge\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nACME challenge + ACME key thumbprint\nURL to call with …\nFor fetching a new nonce used in …\nURL to call with …\nNot yet used\nNon-standard, Wire specific claim. Indicates the consumer …\nURL to call for the acme server to complete the challenge\nContains the error value\nThe entry point for the MLS CoreCrypto library. This …\nContains the success value\nThe ciphersuite identifier presented does not map to a …\nReturns the client’s id as a buffer\nReturns the client’s most recent public signature key as …\nCloses the connection with the local KeyStore\nMLS groups (aka conversation) are the actual entities …\nChecks if a given conversation id exists locally\nDumps the PKI environment as PEM\nReturns true when end-to-end-identity is enabled for the …\nReturns whether the E2EI PKI environment is setup (i.e. …\nVerifies a Group state before joining it\nReturns the argument unchanged.\nReturns the argument unchanged.\nGets the e2ei conversation state from a <code>GroupInfo</code>. Useful …\nGet an immutable view of an <code>MlsConversation</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nProvide the implementation of functions to communicate …\nGenerates a random byte array of the specified size\nsee mls_crypto_provider::MlsCryptoProvider::reseed\nTries to initialize the MLS Central object. Takes a store …\nSame as the MlsCentral::try_new but instead, it uses an in …\nThis is thrown when a client wants to retry sending an …\nThe <code>Conversation</code> trait provides a set of operations that …\nA Conversation Guard wraps a …\nA unique identifier for a group/conversation. The …\nContains the error value\nAn ImmutableConversation wraps a <code>MlsConversation</code>.\nMessage rejected by the delivery service\nThis is a wrapper on top of the OpenMls’s MlsGroup, that …\nContains the success value\nThis happens when the DS cannot flag KeyPackages as …\nAdds new members to the group/conversation\nReturns the ciphersuite of a given conversation\nAllows to remove a pending (uncommitted) proposal. Use …\nCommits all pending proposals of the group\nHelps consumer by providing a deterministic delay in …\nCreates a new group/conversation\nDeserializes a TLS-serialized message, then processes it\nIndicates when to mark a conversation as not verified i.e. …\nSend a commit in a conversation for changing the …\nEncrypts a raw payload then serializes it to the TLS wire …\nReturns the epoch of a given conversation\nDerives a new key from the one in the group, to be used …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nExports the clients from a conversation\nFrom a given conversation, get the identity of the members …\nReturns the raw public key of the single external sender …\nFrom a given conversation, get the identity of the users …\nGroup/conversation id\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nMarks this conversation as child of another. Prerequisite: …\nReturns all members credentials from the group/conversation\nGet actual group members and subtract pending remove …\nReturns all members credentials with their signature …\nsee openmls::group::MlsGroup::propose_add_member\nsee openmls::group::MlsGroup::propose_self_update\nsee openmls::group::MlsGroup::propose_remove_member\nsee openmls::group::MlsGroup::propose_self_update\nRemoves clients from the group/conversation.\nSelf updates the KeyPackage and automatically commits. …\nDestroys a group locally\nWhy was the message rejected by the delivery service?\nRequests that a client with a specified KeyPackage be …\nBasic keypair\nBasic credential i.e. a KeyPair\nNot implemented\nRepresents a x509 certificate chain supplied by the client …\nMLS ciphersuites.\nHandshake messages are always encrypted\nRepresents a MLS client which in our case is the …\nA Client identifier\nUsed by consumers to initializes a MLS client. Encompasses …\nThis error is emitted when the requested conversation …\nThis error is emitted when the requested conversation …\nCredential.\nA cryptobox migration operation failed\nContains GroupInfo changes since previous epoch (not yet …\nIndicates the standalone status of a device Credential in …\nWrap a crate::e2e_identity::Error for recursion.\nIndicates the state of a Conversation regarding end-to-end …\nWhen looking for a X509 credential for a given ciphersuite …\nWrapped 32-byte entropy seed with bounds check\nErrors produced by the root module group\nAny error that occurs during mls transport.\nThe Credential’s certificate is expired\nThis item requires a feature that the core-crypto library …\nPlain old and complete GroupInfo\nGroup epoch. Internally this is stored as a <code>u64</code>. The group …\nRepresents the byte array in MlsGroupInfoBundle\nDefault number of KeyPackages a client generates the first …\nThe MLS group is in an invalid state for an unknown reason\nInvalid Context. This context has been finished and can no …\nGroupInfo encrypted in a JWE\nThe key package struct.\nThe key package struct.\nA reference to a key package. This value uniquely …\nA key store operation failed\nA key store operation failed\nThese errors can be raised from several different modules, …\nA leaf node.\nDH KEM P256 | AES-GCM 128 | SHA2-256 | EcDSA P256\nDH KEM x25519 | AES-GCM 128 | SHA2-256 | Ed25519\nDH KEM x25519 | Chacha20Poly1305 | SHA2-256 | Ed25519\nDH KEM P384 | AES-GCM 256 | SHA2-384 | EcDSA P384\nDH KEM P521 | AES-GCM 256 | SHA2-512 | EcDSA P521\nDH KEM x448 | AES-GCM 256 | SHA2-512 | Ed448\nDH KEM x448 | Chacha20Poly1305 | SHA2-512 | Ed448\nUnexpectedly failed to retrieve group info\nWrap a crate::mls::Error for recursion.\nAn external MLS operation failed\nType safe recursion of MlsConversationDecryptMessage\nConfiguration parameters for <code>MlsCentral</code>\nA wrapper for the OpenMLS Ciphersuite, so that we are able …\nWrap a crate::mls::client::Error for recursion.\nReturned when a commit is created\nWrap a crate::mls::conversation::Error for recursion.\nThe configuration parameters for a group/conversation\nReturned when initializing a conversation through a commit.\nRepresents the potential items a consumer might require …\nWrap a crate::mls::credential::Error for recursion.\nLists all the supported Credential types. Could list in …\nThe configuration parameters for a group/conversation …\nA MLS operation failed, but we captured some context about …\nA <code>MlsGroup</code> represents an MLS group with a high-level API. …\nSpecifies the configuration parameters for a <code>MlsGroup</code>. …\nA GroupInfo with metadata\nGroupInfoEncryptionType\nBefore use with the <code>MlsGroup</code> API, the message has to be …\nInternal representation of proposal to ease further …\nReturned when a Proposal is created. Helps roll backing a …\nAbstraction over a openmls::prelude::hash_ref::ProposalRef …\nRatchetTreeType\nMls Transport Callbacks were not provided\nWrapper over WireFormatPolicy\nContainer enum for leaf and parent nodes.\nAll clients are still Basic. If all client have expired …\nSome clients are either still Basic or their certificate …\nA parent node.\nHandshake messages are never encrypted\nUnencrypted GroupInfo\nUnencrypted GroupInfo\nA Proteus operation failed\nA Proteus operation failed, but we captured some context …\nThe proteus client has been called but has not been …\n32-byte raw entropy seed\nA crate-internal operation failed\nThese errors wrap each of the module-specific errors in …\nRequests that the member with LeafNodeRef removed be …\nThe Credential’s certificate is revoked\nWrap a crate::Error for recursion.\nSimilar mechanism to Add with the distinction that it …\nAll is fine\nA type that represents a group info of which the signature …\nAll clients have a valid E2EI certificate\nContains everything client needs to know after decrypting …\nRepresents the identity claims identifying a client Those …\nX509 certificate\nA x509 certificate generally obtained through e2e identity …\nRepresents the parts of WireIdentity that are specific to …\nReturns the AAD used in the framing.\nAdds members to the group.\nGet the <code>AeadType</code> for this <code>Ciphersuite</code>.\nReturns the key size of the used AEAD.\nReturns the length of the nonce of the AEAD.\nDecrypted text message\nsee MlsConversationDecryptMessage\nGenerates an <code>MlsGroupConfig</code> from this configuration\nReturns the group epoch as a <code>u64</code>.\nExtract the content of an <code>MlsMessageIn</code> after …\nOnly set when the decrypted message is a commit. Contains …\nReturns a builder for <code>MlsGroupConfig</code>\nCreate a key package builder.\nReturns the internal byte array\nX509 certificate identifying this client in the MLS group …\nx509 certificate chain First entry is the leaf certificate …\nCheck whether the this key package supports all the …\nReturns the group’s ciphersuite.\nGet the <code>Ciphersuite</code>.\nGet (unverified) ciphersuite of the verifiable group info.\nThe <code>OpenMls</code> Ciphersuite used in the group\nAll supported ciphersuites\nSets the <code>group_state</code> to <code>MlsGroupState::Operational</code>, thus …\nClear the pending proposals.\nIdentifier for the client to be used by MlsCentral\nUnique client identifier e.g. …\nCloses this provider, which in turns tears down the …\nCommit message adding members to the group\nThe commit message\nCreates a Commit message that covers the pending proposals …\nCalculates the confirmation tag of the current group\nReturns the configuration.\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nCreates an application message. Returns …\nReturns own credential. If the group is inactive, it …\nReturns the credential type.\nIndicates whether the credential is Basic or X509\nNew CRL distribution points that appeared by the …\nNew CRL distribution points that appeared by the …\nsee MlsConversationDecryptMessage\nNew CRL distribution points that appeared by the …\nNew CRL distribution points that appeared by the …\nReturns the <code>CryptoConfig</code>.\nImplementation specific configuration\nDefault capabilities for every generated …\nDelay time in seconds to feed caller timer for committing\nsee MlsConversationDecryptMessage\nDelete this key package and its private key from the key …\nre-export\nName as displayed in the messaging application e.g. …\nDNS domain for which this identity proof was generated …\nIndicates if the <code>payload</code> is encrypted or not\nReturns the epoch.\nReturns the epoch authenticator of the current epoch.\nLike Self::self_update but accepts an explicit node. …\nExport a group info object for this group.\nExports the Ratchet Tree.\nExports a secret from the current epoch. Returns …\nGet a reference to the extensions of this key package.\nEntropy pool seed for the internal PRNG\nReturns the <code>MlsGroupConfig</code> external senders extension\nDelivery service public signature key and credential\nExtract the content of an <code>MlsMessageIn</code> after …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nGenerate a new CredentialBundle (Credential + KeyPair) for …\nGenerates a single new keypackage\nInitializes a raw MLS keypair without an associated client …\nReads the client_id from the leaf certificate\nReads the ‘Not Before’ claim from the leaf certificate\nExtract the unique ClientId from an identifier. Use with …\nReturns a resumption psk for a given epoch. If no …\nGet the group’s <code>Extensions</code>.\nReturns the group ID.\nGet (unverified) group ID of the verifiable group info.\n<code>GroupInfo</code> if the commit is merged\n<code>GroupInfo</code> if the commit is merged\nuser handle e.g. <code>john_wire</code>\nIs the epoch changed after decrypting this message\nsee MlsConversationDecryptMessage\nGet the <code>HashType</code> for this <code>Ciphersuite</code>\nGet the length of the used hash algorithm.\nCompute the <code>KeyPackageRef</code> of this <code>KeyPackage</code>. The …\nGet the <code>HpkeAeadType</code> for this <code>Ciphersuite</code>.\nGet the <code>HpkeConfig</code> for this <code>Ciphersuite</code>.\nGet the public HPKE init key of this key package.\nGet the <code>HpkeKdfType</code> for this <code>Ciphersuite</code>.\nGet the <code>HpkeKemType</code> for this <code>Ciphersuite</code>.\nRetrieves the client’s client id. This is free-form and …\nMLS Group Id\nReturns the identity of a given credential.\nIdentity claims present in the sender credential Present …\nsee MlsConversationDecryptMessage\nIdentity key to be used to instantiate the …\nInitializes the client. If the client’s cryptographic …\nFinalizes initialization using a 2-step process of …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nDuh\nReturns whether the own client is still a member of the …\nIs the conversation still active after receiving this …\nsee MlsConversationDecryptMessage\nReturns whether this client is E2EI capable\nReturns whether we have a PKI env setup\nJoin an existing group through an External Commit. The …\nDuration in seconds after which we will automatically …\nClone keystore (its an <code>Arc</code> internnaly)\nReturns the <code>MlsGroupConfig</code> leaf extensions configuration.\nGet the <code>LeafNode</code> reference.\nLeave the group.\nReturns the <code>MlsGroupConfig</code> lifetime configuration.\nLoads the state from persisted state.\nGet the length of the AEAD tag.\nReturns the <code>MlsGroupConfig</code> max past epochs.\nHow many application messages can be skipped. Use this …\nReturns the <code>Credential</code> of a member corresponding to the …\nReturns a list of <code>Member</code>s in the group.\nMerges the pending <code>StagedCommit</code> if there is one, and …\nMerge a StagedCommit into the group after inspection. As …\nNumber of openmls::prelude::KeyPackage to create when …\nCreates a new group with the creator as the only member …\nCreates and returns a new basic <code>Credential</code> for the given …\nCreates a new group from a <code>Welcome</code> message. Returns an …\nClones the references of the PkiEnvironment and the …\nCreates a new group with a given group ID with the creator …\nInitialize a CryptoProvided with an already-configured …\nCreates and returns a new X509 <code>Credential</code> for the given …\nX509 certificate not after as Unix timestamp\nX509 certificate not before as Unix timestamp\nReturns the <code>MlsGroupConfig</code> number of resumption psks.\nWindow for which decryption secrets are kept within an …\nGet the identity of the client’s <code>Credential</code> owning this …\nReturns a reference to the own <code>LeafNode</code>.\nReturns the leaf index of the client in the tree owning …\nReturns the leaf node of the client in the tree owning …\nReturns the <code>MlsGroupConfig</code> padding size.\nThe GroupInfo\nReturns a reference to the <code>StagedCommit</code> of the most …\nReturns an <code>Iterator</code> over pending proposals.\nLeaf certificate private key\nParses incoming messages from the DS. Checks for syntactic …\nThe proposal message\nA unique identifier of the proposal to rollback it later …\nOnly when decrypted message is a commit, CoreCrypto will …\nsee MlsConversationDecryptMessage\nGenerate a proposal\nCreates proposals to add members to the group.\nCreates proposals to add an external PSK to the key …\nCreates a proposal to update the own leaf node.\nPropose to update the group context extensions. This …\nCreates proposals to add an external PSK to the key …\nCreates proposals to add an external PSK to the key …\nPropose the group to be reinitialized. When commited this …\nCreates proposals to remove members from the group. The …\nCreates proposals to remove members from the group. The …\nCreates proposals to remove members from the group. The …\nCreates proposals to add an external PSK to the key …\nCreates a proposal to update the own leaf node.\nCreates a proposal to update the own leaf node.\nPrune the provided KeyPackageRefs from the keystore\nIndicates if the <code>payload</code> contains a full, partial or …\nReInits the group. If there are any proposals in the …\nRemoves members from the group.\nRemoves a specific proposal from the store.\nRequests <code>count</code> keying material to be present and returns a …\nReseeds the internal CSPRNG entropy pool with a brand new …\nReturns the resumption PSK secret of the current epoch.\nPersists the state.\nUpdates the own leaf node.\nClientId of the sender of the message being decrypted. …\nsee MlsConversationDecryptMessage\nReturns the <code>MlsGroupConfig</code> sender ratchet configuration.\nX509 certificate serial number\nSets the AAD used in the framing.\nSets the configuration.\nSets the entropy seed\nMeh\nGet the <code>SignatureScheme</code> for this <code>Ciphersuite</code>.\nWhat happened\nWhat happened\nWhat happened\nWhat happened with the keystore\nVerify that this key package is valid disregarding the …\nReturns <code>true</code> if the internal state has changed and needs …\nStatus of the Credential at the moment T when this object …\nLocation where the SQLite/IndexedDB database will be stored\nStores a standalone proposal in the internal ProposalStore\nDo whatever it takes not to clone the RatchetTree\nMLS thumbprint\nSerializes both wrapped objects into TLS and return them …\nSerializes both wrapped objects into TLS and return them …\nSerializes both wrapped objects into TLS and return them …\nReturns the <code>MlsGroupConfig</code> group extensions configuration.\nCreates a new instance of the configuration.\nInitialize a CryptoProvider with a backend following the …\nReturns a <code>CredentialWithKey</code> from the unverified payload\nAllows to retrieve the underlying key store directly\nUpdates the extensions of the group\nReplaces the PKI env currently in place\nReturns the <code>MlsGroupConfig</code> boolean flag that indicates …\nReturns the count of valid, non-expired, unclaimed …\nVerify that this key package is valid:\nA welcome message for new members to join the group\nA welcome message if there are pending Add proposals\nReturns the wire format.\nReturns the <code>MlsGroupConfig</code> wire format policy.\nDefines if handshake messages are encrypted or not\nIn case ‘credential_type’ is MlsCredentialType::X509 …\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat was happening in the caller\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nWhat happened\nProteus counterpart of crate::mls::MlsCentral\nProteus Session wrapper, that contains the identifier and …\nProteus session IDs, it seems it’s basically a string\nDecrypts a message for this Proteus session\nEncrypts a message for this Proteus session\nProteus Public key hex-encoded fingerprint\nReturns the public key fingerprint of the local identity …\nHex-encoded fingerprint of the given prekey\nReturns the public key fingerprint of the remote identity …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the session identifier\nProteus identity keypair\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the Proteus last resort prekey ID (u16::MAX = …\nCreates a new session from a prekey\nInitializes the ProteusCentral")