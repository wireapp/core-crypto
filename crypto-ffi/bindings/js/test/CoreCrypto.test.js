const puppeteer = require("puppeteer");
const { exec } = require("child_process");

let browser;

async function initBrowser(args = { captureLogs: true }) {
  if (!browser) {
    browser = await puppeteer.launch();
  }
  const context = await browser.createIncognitoBrowserContext();
  const page = await context.newPage();
  if (args.captureLogs) {
    page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  }

  await page.goto("http://localhost:3000");
  return [context, page];
}

async function execAsync(command, options = {}) {
  return new Promise((resolve, reject) => exec(command, options, (err, stdout, stderr) => {
    if (err) {
      err.stderr = stderr;
      err.stdout = stdout;
      return reject(err);
    }

    resolve([stdout, stderr]);
  }));
}

test("tsc import of package", async () => {
  const args = [
    "--moduleResolution node",
    "-t es2020",
    "-m es2020",
    "--lib es2020",
    "--noEmit"
  ];

  try {
    await execAsync(
      `npx --package=typescript@latest -- tsc ${args.join(' ')} ./crypto-ffi/bindings/js/test/tsc-import-test.ts`,
    );
  } catch(cause) {
    throw new Error(`Couldn't build @wireapp/core-crypto import.

      tsc output:
      ${cause.stdout}
      ${cause.stderr}`, {
      cause
    });
  }
}, 10000);

test("init", async () => {
  const [ctx, page] = await initBrowser();

  const version = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const cc = await CoreCrypto.init({
      databaseName: "test init",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "test",
    });

    return CoreCrypto.version();
  });

  expect(version).toMatch(process.env.npm_package_version);

  await page.close();
  await ctx.close();
});

test("can use groupInfo enums", async () => {
  const [ctx, page] = await initBrowser();

  const [GroupInfoEncryptionType, RatchetTreeType] = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType, GroupInfoEncryptionType, RatchetTreeType } = await import ("./corecrypto.js");

    window.GroupInfoEncryptionType = GroupInfoEncryptionType;
    window.RatchetTreeType = RatchetTreeType;
    window.CoreCrypto = CoreCrypto;
    window.Ciphersuite = Ciphersuite;
    window.CredentialType = CredentialType.Basic;

    return [GroupInfoEncryptionType, RatchetTreeType];
  });

  expect(GroupInfoEncryptionType.Plaintext).toBe(0x01);
  expect(GroupInfoEncryptionType.JweEncrypted).toBe(0x02);
  expect(await page.evaluate(() => window.GroupInfoEncryptionType.Plaintext)).toBe(0x01);
  expect(await page.evaluate(() => window.GroupInfoEncryptionType.JweEncrypted)).toBe(0x02);
  expect(RatchetTreeType.Full).toBe(0x01);
  expect(RatchetTreeType.Delta).toBe(0x02);
  expect(RatchetTreeType.ByRef).toBe(0x03);
  expect(await page.evaluate(() => window.RatchetTreeType.Full)).toBe(0x01);
  expect(await page.evaluate(() => window.RatchetTreeType.Delta)).toBe(0x02);
  expect(await page.evaluate(() => window.RatchetTreeType.ByRef)).toBe(0x03);

  const pgs = await page.evaluate(async () => {
    const ciphersuite = window.Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const client1Config = {
      databaseName: "test init",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "test",
    };

    const client2Config = {
      databaseName: "roundtrip message test 2",
      key: "test2",
      ciphersuites: [ciphersuite],
      clientId: "test2",
    };

    const cc = await window.CoreCrypto.init(client1Config);
    const cc2 = await window.CoreCrypto.init(client2Config);

    const [kp] = await cc2.clientKeypackages(ciphersuite, 1);

    const encoder = new TextEncoder();
    const conversationId = encoder.encode("testConversation");

    await cc.createConversation(conversationId, window.CredentialType);

    const { groupInfo: groupInfo } = await cc.addClientsToConversation(conversationId, [
      { id: encoder.encode(client2Config.clientId), kp },
    ]);

    return groupInfo;
  });

  expect(pgs.encryptionType).toBe(0x01);
  expect(pgs.encryptionType).toBe(GroupInfoEncryptionType.Plaintext);
  expect(pgs.ratchetTreeType).toBe(0x01);
  expect(pgs.ratchetTreeType).toBe(RatchetTreeType.Full);

  await page.close();
  await ctx.close();
});

test("can import ciphersuite enum", async () => {
  const [ctx, page] = await initBrowser();

  const enumRepr = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    window.cc = await CoreCrypto.init({
      databaseName: "test ciphersuite",
      key: "test",
      ciphersuites: [Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
      clientId: "test",
    });

    window.ciphersuite = Ciphersuite;
    return Ciphersuite;
  });

  expect(await page.evaluate(() => window.ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)).toBe(0x0001);
  expect(await page.evaluate(() => window.ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256)).toBe(0x0002);
  expect(await page.evaluate(() => window.ciphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)).toBe(0x0003);
  expect(await page.evaluate(() => window.ciphersuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448)).toBe(0x0004);
  expect(await page.evaluate(() => window.ciphersuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521)).toBe(0x0005);
  expect(await page.evaluate(() => window.ciphersuite.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448)).toBe(0x0006);
  expect(await page.evaluate(() => window.ciphersuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384)).toBe(0x0007);

  await page.close();
  await ctx.close();
});

test("external entropy", async () => {
  const [ctx, page] = await initBrowser();

  // Test vectors 1 and 2 from
  // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
  const vector1 = Uint32Array.from([
    0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
    0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
    0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
    0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
  ]);
  const vector2 = Uint32Array.from([
    0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73,
    0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32,
    0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874,
    0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b,
  ]);

  let [produced1, produced2] = await page.evaluate(async (expected1Length, expected2Length) => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    // Null byte seed
    const seed = new Uint8Array(32);

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const cc = await CoreCrypto.init({
      databaseName: "test init",
      key: "test",
      clientId: "test",
      ciphersuites: [ciphersuite],
      entropySeed: seed,
    });

    // Reset it because the `init` method performed some RNG calls and made it "dirty"
    await cc.reseedRng(seed);

    const produced1 = await cc.randomBytes(expected1Length);
    const produced2 = await cc.randomBytes(expected2Length);
    return [produced1, produced2];
  }, vector1.length * vector1.BYTES_PER_ELEMENT, vector2.length * vector2.BYTES_PER_ELEMENT);

  produced1 = Uint8Array.from(Object.values(produced1));
  produced2 = Uint8Array.from(Object.values(produced2));
  // Use a DataView to solve endianness issues
  const produced1AsU32Array = new Uint32Array(produced1.buffer);
  const produced2AsU32Array = new Uint32Array(produced2.buffer);

  expect(produced1AsU32Array).toStrictEqual(vector1);
  expect(produced2AsU32Array).toStrictEqual(vector2);

  await page.close();
  await ctx.close();
});

test("externally generated clients", async () => {
  const [ctx, page] = await initBrowser();

  await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credentialType = CredentialType.Basic;
    const alice = await CoreCrypto.deferredInit({
      databaseName: "extgen alice test",
      key: "test",
      ciphersuites: [ciphersuite],
    });

    const signaturePks = await alice.mlsGenerateKeypair([ciphersuite]);

    const shinyClientId = "my:shiny:client@wire.com";
    const encoder = new TextEncoder();
    const clientId = encoder.encode(shinyClientId);

    await alice.mlsInitWithClientId(clientId, signaturePks, [ciphersuite]);

    const bob = await CoreCrypto.init({
      databaseName: "extgen bob test",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "bob",
    });

    const [bobKp, ] = await bob.clientKeypackages(ciphersuite, 1);

    const conversationId = encoder.encode("testConversation");

    await alice.createConversation(conversationId, credentialType);

    const memberAdded = await alice.addClientsToConversation(conversationId, [
      { id: encoder.encode("bob"), kp: bobKp },
    ]);

    if (!memberAdded) {
      throw new Error("no welcome message was generated");
    }

    await alice.commitAccepted(conversationId);

    const welcomeConversationId = await bob.processWelcomeMessage(memberAdded.welcome);

    if (!conversationId.every((val, i) => val === welcomeConversationId[i])) {
      throw new Error(`conversationId mismatch, got ${welcomeConversationId}, expected ${conversationId}`);
    }

    const messageText = "Hello world!";
    const messageBuffer = encoder.encode(messageText);

    const encryptedMessage = await alice.encryptMessage(
      conversationId,
      messageBuffer,
    );

    const decryptedMessage = await bob.decryptMessage(welcomeConversationId, encryptedMessage);

    if (!decryptedMessage.message) {
      return new Error("alice -> bob decrypted message isn't an application message");
    }

    if (!decryptedMessage.message.every((val, i) => val === messageBuffer[i])) {
      throw new Error("alice -> bob message differs from bob's point of view");
    }

    const bobEncryptedMessage = await bob.encryptMessage(
      conversationId,
      messageBuffer
    );

    const aliceDecryptedMessage = await alice.decryptMessage(
      conversationId,
      bobEncryptedMessage
    );

    if (!aliceDecryptedMessage.message) {
      return new Error("bob -> alice decrypted message isn't an application message");
    }

    if (!aliceDecryptedMessage.message.every((val, i) => val === messageBuffer[i])) {
      throw new Error("bob -> alice message differs from alice's point of view");
    }
  })

  await page.close();
  await ctx.close();
});

test("get client public key", async () => {
  const [ctx, page] = await initBrowser();

  const pkLength = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const cc = await CoreCrypto.init({
      databaseName: "get client public key",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "test",
    });

    const len = (await cc.clientPublicKey(ciphersuite)).length;
    await cc.wipe();
    return len;
  });

  expect(pkLength).toBe(32);

  await page.close();
  await ctx.close();
});

test("get client keypackages", async () => {
  const [ctx, page] = await initBrowser();

  const kpNumber = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const cc = await CoreCrypto.init({
      databaseName: "get client keypackages",
      key: "test",
      clientId: "test",
      ciphersuites: [ciphersuite],
    });

    const kps = await cc.clientKeypackages(ciphersuite, 20);
    const len = kps.length;

    await cc.wipe();

    return len;
  });

  expect(kpNumber).toBe(20);

  await page.close();
  await ctx.close();
});

test("encrypt message", async () => {
  const [ctx, page] = await initBrowser();

  const msgLen = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credentialType = CredentialType.Basic;
    const cc = await CoreCrypto.init({
      databaseName: "encrypt message",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "test",
    });

    const encoder = new TextEncoder();

    const conversationId = encoder.encode("testConversation");

    await cc.createConversation(conversationId, credentialType);

    const encryptedMessage = await cc.encryptMessage(
      conversationId,
      encoder.encode("Hello World!")
    );

    const len = encryptedMessage.length;

    await cc.wipe();

    return len;
  });

  expect(msgLen).toBeGreaterThan(0);

  await page.close();
  await ctx.close();
});

test("roundtrip message", async () => {
  const [ctx, page] = await initBrowser();
  const [ctx2, page2] = await initBrowser();

  const messageText = "Hello World!";
  const conversationId = "testConversation";
  const clientId2 = "test2";

  let kp = await page2.evaluate(async (clientId) => {
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const config = {
        databaseName: "roundtrip message test 2",
        key: "test2",
        clientId: clientId,
        ciphersuites: [ciphersuite],
    };

    const cc2 = await CoreCrypto.init(config);

    const [kp] = await cc2.clientKeypackages(ciphersuite, 1);
    await cc2.close();
    return kp;
  }, clientId2);

  kp = Uint8Array.from(Object.values(kp));

  let [welcome, message] = await page.evaluate(async (kp, messageText, conversationId, clientId2) => {
    const { CoreCrypto, Ciphersuite, CredentialType } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credentialType = CredentialType.Basic;
    const config = {
        databaseName: "roundtrip message test 1",
        key: "test",
        clientId: "test",
        ciphersuites: [ciphersuite],
    };

    const cc = await CoreCrypto.init(config);

    const encoder = new TextEncoder();

    const conversationIdBuffer = encoder.encode(conversationId);

    await cc.createConversation(conversationIdBuffer, credentialType);

    const memberAdded = await cc.addClientsToConversation(conversationIdBuffer, [
      { id: encoder.encode(clientId2), kp: Uint8Array.from(Object.values(kp)) },
    ]);

    await cc.commitAccepted(conversationIdBuffer);

    if (!memberAdded) {
      throw new Error("no welcome message was generated");
    }

    const message = await cc.encryptMessage(
      conversationIdBuffer,
      encoder.encode(messageText)
    );

    return [memberAdded, message];
  }, kp, messageText, conversationId, clientId2);

  welcome.welcome = Uint8Array.from(welcome.welcome);
  welcome.commit = Uint8Array.from(welcome.commit);
  welcome.groupInfo = Uint8Array.from(welcome.groupInfo);

  message = Uint8Array.from(Object.values(message));

  const isMessageIdentical = await page2.evaluate(async (welcome, message, messageText, conversationId, clientId) => {
    const welcomeMessage = Uint8Array.from(Object.values(welcome));
    const encryptedMessage = Uint8Array.from(Object.values(message));
    const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

    const encoder = new TextEncoder();

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const config = {
      databaseName: "roundtrip message test 2",
      key: "test2",
      clientId: clientId,
      ciphersuites: [ciphersuite],
    };
    const cc2 = await CoreCrypto.init(config);

    const messageBuffer = encoder.encode(messageText);

    const conversationIdBuffer = encoder.encode(conversationId);

    const welcomeConversationId = await cc2.processWelcomeMessage(welcomeMessage);
    if (!conversationIdBuffer.every((val, i) => val === welcomeConversationId[i])) {
      throw new Error(`conversationId mismatch, got ${welcomeConversationId}, expected ${conversationIdBuffer}`);
    }

    const decryptedMessage = await cc2.decryptMessage(welcomeConversationId, encryptedMessage);

    if (!decryptedMessage.message) {
      return false;
    }

    return decryptedMessage.message.every((val, i) => val === messageBuffer[i]);
  }, welcome.welcome, message, messageText, conversationId, clientId2);

  expect(isMessageIdentical).toBe(true);

  await page.close();
  await page2.close();
  await ctx.close();
  await ctx2.close();
}, 20000);

test("callbacks default to false when not async", async () => {
  const [ctx, page] = await initBrowser({ captureLogs: false });

  const result = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType, ExternalProposalType } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credentialType = CredentialType.Basic;
    const client1Config = {
      databaseName: "test cb",
      key: "test",
      clientId: "test",
      ciphersuites: [ciphersuite],
    };

    const client2Config = {
      databaseName: "test cb2",
      key: "test",
      clientId: "test2",
      ciphersuites: [ciphersuite],
    };

    const callbacks = {
      authorize(conversationId, clientId) {
        return true;
      },
      userAuthorize(conversationId, externalClientId, existingClients) {
        return true;
      },
      clientIsExistingGroupUser(conversationId, clientId, existingClients, parentConversationIds) {
        return true;
      }
    };

    const cc = await CoreCrypto.init(client1Config);

    await cc.registerCallbacks(callbacks);

    const cc2 = await CoreCrypto.init(client2Config);
    const [cc2Kp] = await cc2.clientKeypackages(ciphersuite, 1);

    const encoder = new TextEncoder();

    const conversationId = encoder.encode("Test conversation");

    await cc.createConversation(conversationId, credentialType);

    try {
      const creationMessage = await cc.addClientsToConversation(conversationId, [
        { id: encoder.encode(client2Config.clientId), kp: cc2Kp },
      ]);
    } catch(e) {
      return false;
    }

    return true;
  });

  expect(result).toBe(false);
});

test("ext commits|proposals & callbacks", async () => {
  const [ctx, page] = await initBrowser();

  const callbacksResults = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType, ExternalProposalType } = await import("./corecrypto.js");

    let theoreticalEpoch = 0;

    const assertEpoch = async (conversationId, expected, client) => {
      const got = await client.conversationEpoch(conversationId);
      if (parseInt(expected, 10) !== parseInt(got, 10)) {
        throw new Error(`Epoch mismatch, expected ${expected}; got ${got}`);
      }
    };

    const callbacksResults = {
      authorize: false,
      userAuthorize: false,
      clientIsExistingGroupUser: false,
    };

    const credentialType = CredentialType.Basic;
    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const client1Config = {
      databaseName: "test init",
      key: "test",
      clientId: "test",
      ciphersuites: [ciphersuite],
    };

    const client2Config = {
      databaseName: "test init2",
      key: "test",
      clientId: "test2",
      ciphersuites: [ciphersuite],
    };

    const clientExtProposalConfig = {
      databaseName: "test init ext proposal",
      key: "test",
      clientId: "testExternalProposal",
      ciphersuites: [ciphersuite],
    };

    const clientExtCommitConfig = {
      databaseName: "test init ext commit",
      key: "test",
      clientId: "testExternalCommit",
      ciphersuites: [ciphersuite],
    };

    const callbacks = {
      async authorize(conversationId, clientId) {
        callbacksResults.authorize = true;
        return true;
      },
      async userAuthorize(conversationId, externalClientId, existingClients) {
        callbacksResults.userAuthorize = true;
        return true;
      },
      async clientIsExistingGroupUser(conversationId, clientId, existingClients) {
        callbacksResults.clientIsExistingGroupUser = true;
        return true;
      }
    };

    const cc = await CoreCrypto.init(client1Config);

    await cc.registerCallbacks(callbacks);

    const cc2 = await CoreCrypto.init(client2Config);
    const [cc2Kp] = await cc2.clientKeypackages(ciphersuite, 1);

    const ccExternalProposal = await CoreCrypto.init(clientExtProposalConfig);
    const ccExternalCommit = await CoreCrypto.init(clientExtCommitConfig);

    const encoder = new TextEncoder();

    const conversationId = encoder.encode("Test conversation");

    await cc.createConversation(conversationId, credentialType);

    // ! This should trigger the authorize callback
    const creationMessage = await cc.addClientsToConversation(conversationId, [
      { id: encoder.encode(client2Config.clientId), kp: cc2Kp },
    ]);

    await cc.commitAccepted(conversationId);
    await assertEpoch(conversationId, ++theoreticalEpoch, cc);

    if (!callbacksResults.authorize) {
      throw new Error("authorize callback wasn't triggered");
    }

    await cc2.processWelcomeMessage(creationMessage.welcome);


    const extProposal = await ccExternalProposal.newExternalProposal(ExternalProposalType.Add, {
      conversationId,
      // ? Be careful; If you change anything above the epoch might change because right now it's a guesswork
      // ? Normally, clients should obtain the epoch *somehow*, usually from the MLS DS, but we just guess that since we only added
      // ? one client, the epoch should only have moved from 0 (initial state) to 1 (added 1 client -> committed)
      epoch: theoreticalEpoch,
      ciphersuite: ciphersuite,
      credentialType: credentialType,
    });

    // ! This should trigger the clientIsExistingGroupUser callback
    const somethingProposal = await cc.decryptMessage(conversationId, extProposal);

    const extProposalCommit = await cc.commitPendingProposals(conversationId);
    await cc.commitAccepted(conversationId);
    await assertEpoch(conversationId, ++theoreticalEpoch, cc);

    if (!callbacksResults.clientIsExistingGroupUser) {
      throw new Error("clientIsExistingGroupUser callback wasn't triggered");
    }

    const gi = extProposalCommit.groupInfo;

    const extCommit = await ccExternalCommit.joinByExternalCommit(gi.payload, credentialType);
    // ! This should trigger the userAuthorize callback
    const somethingCommit = cc.decryptMessage(conversationId, extCommit.commit);

    await cc.commitAccepted(conversationId);
    await assertEpoch(conversationId, ++theoreticalEpoch, cc);

    await ccExternalCommit.mergePendingGroupFromExternalCommit(conversationId);

    if (!callbacksResults.userAuthorize) {
      throw new Error("userAuthorize callback wasn't triggered");
    }

    return callbacksResults;
  });

  expect(callbacksResults.authorize).toBe(true);
  expect(callbacksResults.clientIsExistingGroupUser).toBe(true);
  expect(callbacksResults.userAuthorize).toBe(true);

  await page.close();
  await ctx.close();
});

test("proteusError", async () => {
  const [ctx, page] = await initBrowser();

  await page.evaluate(async () => {
    const { CoreCryptoError } = await import("./corecrypto.js");

    const richErrorJSON = {
      errorName: "ErrorTest",
      message: "Hello world",
      rustStackTrace: "test",
      proteusErrorCode: 22
    };

    const testStr = `${richErrorJSON.message}\n\n${JSON.stringify(richErrorJSON)}`;

    const e = new Error(testStr);
    const ccErr = CoreCryptoError.fromStdError(e);
    const ccErr2 = CoreCryptoError.build(e.message);


    if (ccErr.name !== ccErr2.name || ccErr.name !== "ErrorTest") {
      throw new Error("Errors are different", { cause: ccErr });
    }

    if (ccErr.proteusErrorCode !== 22) {
      throw new Error("Errors are different", { cause: ccErr });
    }

    try {
      throw ccErr;
    } catch(e) {
      if (!e instanceof CoreCryptoError) {
        throw new Error("Error is of the incorrect class");
      }
    }
  });

  await page.close();
  await ctx.close();
});

test("proteus", async () => {
  const [ctx, page] = await initBrowser();

  await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CoreCryptoError } = await import("./corecrypto.js");

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const client1Config = {
      databaseName: "proteus test1",
      key: "test",
      ciphersuites: [ciphersuite],
    };

    const client2Config = {
      databaseName: "proteus test2",
      key: "test",
      ciphersuites: [ciphersuite],
    };

    const message = "Hello world!";

    const alice = await CoreCrypto.deferredInit(client1Config);
    await alice.proteusInit();

    const lrPkId = CoreCrypto.proteusLastResortPrekeyId();
    const u16MAX = Math.pow(2, 16) - 1;
    if (lrPkId !== u16MAX) {
      throw new Error(`Last resort Prekey ID differs from expected ${u16MAX}, got ${lrPkId}`);
    }

    const aliceLrPk1 = await alice.proteusLastResortPrekey();
    const aliceLrPk2 = await alice.proteusLastResortPrekey();
    if (!aliceLrPk1.every((val, i) => val === aliceLrPk2[i])) {
      throw new Error(`Last Resort prekey differs between runs, indicating that it has been regenerated!

        run1: [${aliceLrPk1.join(", ")}]
        run2: [${aliceLrPk2.join(", ")}]
      `);
    }

    const bob = await CoreCrypto.deferredInit(client2Config);
    await bob.proteusInit();

    const bobPrekey = await bob.proteusNewPrekey(10);

    await alice.proteusSessionFromPrekey("ab", bobPrekey);
    const aliceBobMessage = await alice.proteusEncrypt("ab", encoder.encode(message));

    const decrypted = decoder.decode(await bob.proteusSessionFromMessage("ba", aliceBobMessage));

    if (decrypted !== message) {
      throw new Error("Message decrypted by bob doesn't match message sent by alice");
    }

    let proteusErrCode = 0;

    proteusErrCode = await bob.proteusLastErrorCode();
    if (proteusErrCode !== 0) {
      throw new Error(`bob has encountered an unlikely error [code ${proteusErrCode}`);
    }

    try {
      await bob.proteusSessionFromMessage("ba", aliceBobMessage);
      throw new TypeError("Error not thrown when CoreCryptoError[proteus error 101] should be triggered, something is wrong");
    } catch (e) {
      if (e instanceof CoreCryptoError) {
        const errorCode = e.proteusErrorCode;
        if (errorCode !== 101) {
          throw new TypeError(`CoreCryptoError has been thrown, but the code isn't correct. Expected 101, got ${errorCode}`);
        }

        proteusErrCode = await bob.proteusLastErrorCode();
        if (proteusErrCode !== 101) {
          throw new TypeError(`The \`proteusLastErrorCode()\` method isn't consistent with the code returned. Expected 101, got ${proteusErrCode}`);
        }

        return null;
      } else if (e instanceof TypeError) {
        throw e;
      } else {
        throw new Error(`Unknown error type\nCause[${typeof e}]:\n${e}`, { cause: e });
      }
    }
  });


  await page.close();
  await ctx.close();
});

test("end-to-end-identity", async () => {
  const [ctx, page] = await initBrowser();

  await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CoreCryptoError } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const cc = await CoreCrypto.deferredInit({
      databaseName: "e2ei test",
      key: "test",
      ciphersuites: [ciphersuite],
    });

    const encoder = new TextEncoder();
    const jsonToByteArray = json => encoder.encode(JSON.stringify(json, null, 0));

    const clientId = "NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg:6c1866f567616f31@wire.com";
    const displayName = "Alice Smith";
    const handle = "alice_wire";
    const expiryDays = 90;

    let enrollment = await cc.e2eiNewEnrollment(clientId, displayName, handle, expiryDays, ciphersuite);

    const directoryResp = {
        "newNonce": "https://example.com/acme/new-nonce",
        "newAccount": "https://example.com/acme/new-account",
        "newOrder": "https://example.com/acme/new-order"
    };
    enrollment.directoryResponse(jsonToByteArray(directoryResp));

    const previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
    const accountReq = enrollment.newAccountRequest(previousNonce);

    const accountResp = {
        "status": "valid",
        "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
    };
    enrollment.newAccountResponse(jsonToByteArray(accountResp));

    const newOrderReq = enrollment.newOrderRequest(previousNonce);

    const newOrderResp = {
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
            "https://example.com/acme/authz/PAniVnsZcis",
        ],
        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
    };
    const newOrder = enrollment.newOrderResponse(jsonToByteArray(newOrderResp));

    const authzUrl = "https://example.com/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm";
    const authzReq = enrollment.newAuthzRequest(authzUrl, previousNonce);

    const authzResp = {
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
    };
    const authz = enrollment.newAuthzResponse(jsonToByteArray(authzResp));

    const backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
    const dpopTokenExpirySecs = 3600;
    const clientDpopToken = enrollment.createDpopToken(dpopTokenExpirySecs, backendNonce);

    const accessToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ";
    const dpopChallengeReq = enrollment.newDpopChallengeRequest(accessToken, previousNonce);
    const dpopChallengeResp = {
        "type": "wire-dpop-01",
        "url": "https://example.com/acme/chall/prV_B7yEyA4",
        "status": "valid",
        "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
    };
    enrollment.newChallengeResponse(jsonToByteArray(dpopChallengeResp));

    // simulate the OAuth redirect
    let storeHandle = await cc.e2eiEnrollmentStash(enrollment);
    enrollment = await cc.e2eiEnrollmentStashPop(storeHandle);

    const idToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ";
    const oidcChallengeReq = enrollment.newOidcChallengeRequest(idToken, previousNonce);
    const oidcChallengeResp = {
        "type": "wire-oidc-01",
        "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
        "status": "valid",
        "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
    };
    enrollment.newChallengeResponse(jsonToByteArray(oidcChallengeResp));

    const orderUrl = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";
    const checkOrderReq = enrollment.checkOrderRequest(orderUrl, previousNonce);

    const checkOrderResp = {
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
    };
    enrollment.checkOrderResponse(jsonToByteArray(checkOrderResp));

    const finalizeReq = enrollment.finalizeRequest(previousNonce);
    const finalizeResp = {
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
    };
    enrollment.finalizeResponse(jsonToByteArray(finalizeResp));

    const certificateReq = enrollment.certificateRequest(previousNonce);

    const certificateResp = "-----BEGIN CERTIFICATE-----\n" +
        "MIICIjCCAcigAwIBAgIQKRapc1IDZvJc88zB+vlrNTAKBggqhkjOPQQDAjAuMQ0w\n" +
        "CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\n" +
        "MzA2MDYxMjAzMDlaFw0zMzA2MDMxMjAzMDlaMCkxETAPBgNVBAoTCHdpcmUuY29t\n" +
        "MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhACqExBb1vLgMNq8GkLgM\n" +
        "R+W+dp0szvjYL2GybNkPKzoto4H7MIH4MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\n" +
        "DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUaPHUDloFLv5o4j4J4EmvoYToqHcwHwYD\n" +
        "VR0jBBgwFoAUlbTj2u59dFDGs1LVj0GrGKJUK/gwcgYDVR0RBGswaYYVaW06d2ly\n" +
        "ZWFwcD1hbGljZV93aXJlhlBpbTp3aXJlYXBwPVl6QXpZalZoT1dRMFpqSXdOR0k1\n" +
        "T1Rrek9HRTRPREptT1RjeE0yWm1PR00vNDk1OWJjNmFiMTJmMjg0NkB3aXJlLmNv\n" +
        "bTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAw\n" +
        "RQIhAIRaoCuyIAXtpAsUhZvJb7Qb+2EKsc9iIzHtsBU5MtVMAiAz2Tm4ojAolq4J\n" +
        "ZjWPVSDz4AN1gd200EpS50cS/mLDqw==\n" +
        "-----END CERTIFICATE-----\n" +
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIBuTCCAV6gAwIBAgIQYiSIW2ebbC32Iq5YO0AyLDAKBggqhkjOPQQDAjAmMQ0w\n" +
        "CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNjA2MTIw\n" +
        "MzA2WhcNMzMwNjAzMTIwMzA2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\n" +
        "aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEKu\n" +
        "1Ekx95MKKr9FxUspwFtyErShqoPKZNlyfz8u8lmvi50FpwqUXem1EoOUOm7UHy5m\n" +
        "HJO513uJY0Q/ecZUwAKjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n" +
        "AQH/AgEAMB0GA1UdDgQWBBSVtOPa7n10UMazUtWPQasYolQr+DAfBgNVHSMEGDAW\n" +
        "gBSy9uS81ABjfHbkz42x/Gf160mt1jAKBggqhkjOPQQDAgNJADBGAiEAq/T83XSg\n" +
        "7/GN+fUi79bzXI9oQdDuXqyhGnjIXtr2D8YCIQCuS1tZQm6lVcDZMWYQWLfv/b46\n" +
        "GjWuPgx1fD4m+ar9Tw==\n" +
        "-----END CERTIFICATE-----";

    await cc.e2eiMlsInit(enrollment, certificateResp);
  });

  await page.close();
  await ctx.close();
});

test("e2ei is conversation degraded", async () => {
  const [ctx, page] = await initBrowser();

  const isDegraded = await page.evaluate(async () => {
    const { CoreCrypto, Ciphersuite, CredentialType } = await import("./corecrypto.js");

    const ciphersuite = Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    const credentialType = CredentialType.Basic;
    const cc = await CoreCrypto.init({
      databaseName: "is degraded",
      key: "test",
      ciphersuites: [ciphersuite],
      clientId: "test",
    });

    const encoder = new TextEncoder();
    const conversationId = encoder.encode("degradedConversation");
    await cc.createConversation(conversationId, credentialType);

    const isDegraded = await cc.e2eiIsDegraded(conversationId);

    await cc.wipe();
    return isDegraded;
  });

  expect(isDegraded).toBe(true);

  await page.close();
  await ctx.close();
});
