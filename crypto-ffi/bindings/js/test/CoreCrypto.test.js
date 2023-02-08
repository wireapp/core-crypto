const puppeteer = require("puppeteer");
const { exec } = require("child_process");

let browser;

async function initBrowser() {
  if (!browser) {
    browser = await puppeteer.launch();
  }
  const context = await browser.createIncognitoBrowserContext();
  const page = await context.newPage();
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));

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
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      databaseName: "test init",
      key: "test",
      clientId: "test",
    });

    return CoreCrypto.version();
  });

  expect(version).toMatch("0.6.0");

  await page.close();
  await ctx.close();
});

test("can use pgs enums", async () => {
  const [ctx, page] = await initBrowser();

  const [PublicGroupStateEncryptionType, RatchetTreeType] = await page.evaluate(async () => {
    const { CoreCrypto, PublicGroupStateEncryptionType, RatchetTreeType } = await import ("./corecrypto.js");

    window.PublicGroupStateEncryptionType = PublicGroupStateEncryptionType;
    window.RatchetTreeType = RatchetTreeType;
    window.CoreCrypto = CoreCrypto;

    return [PublicGroupStateEncryptionType, RatchetTreeType];
  });

  expect(PublicGroupStateEncryptionType.Plaintext).toBe(0x01);
  expect(PublicGroupStateEncryptionType.JweEncrypted).toBe(0x02);
  expect(await page.evaluate(() => window.PublicGroupStateEncryptionType.Plaintext)).toBe(0x01);
  expect(await page.evaluate(() => window.PublicGroupStateEncryptionType.JweEncrypted)).toBe(0x02);
  expect(RatchetTreeType.Full).toBe(0x01);
  expect(RatchetTreeType.Delta).toBe(0x02);
  expect(RatchetTreeType.ByRef).toBe(0x03);
  expect(await page.evaluate(() => window.RatchetTreeType.Full)).toBe(0x01);
  expect(await page.evaluate(() => window.RatchetTreeType.Delta)).toBe(0x02);
  expect(await page.evaluate(() => window.RatchetTreeType.ByRef)).toBe(0x03);

  const pgs = await page.evaluate(async () => {
    const client1Config = {
      databaseName: "test init",
      key: "test",
      clientId: "test",
    };

    const client2Config = {
      databaseName: "roundtrip message test 2",
      key: "test2",
      clientId: "test2",
    };

    const cc = await window.CoreCrypto.init(client1Config);
    const cc2 = await window.CoreCrypto.init(client2Config);

    const [kp] = await cc2.clientKeypackages(1);

    const encoder = new TextEncoder();
    const conversationId = encoder.encode("testConversation");

    await cc.createConversation(conversationId);

    const { publicGroupState } = await cc.addClientsToConversation(conversationId, [
      { id: encoder.encode(client2Config.clientId), kp },
    ]);

    return publicGroupState;
  });

  expect(pgs.encryptionType).toBe(0x01);
  expect(pgs.encryptionType).toBe(PublicGroupStateEncryptionType.Plaintext);
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
    const { CoreCrypto } = await import("./corecrypto.js");

    // Null byte seed
    const seed = new Uint8Array(32);

    const cc = await CoreCrypto.init({
      databaseName: "test init",
      key: "test",
      clientId: "test",
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
    const { CoreCrypto } = await import("./corecrypto.js");

    const alice = await CoreCrypto.deferredInit({
      databaseName: "extgen alice test",
      key: "test"
    });

    const signaturePk = await alice.mlsGenerateKeypair();

    const shinyClientId = "my:shiny:client@wire.com";
    const encoder = new TextEncoder();
    const clientId = encoder.encode(shinyClientId);

    await alice.mlsInitWithClientId(clientId, signaturePk);

    const bob = await CoreCrypto.init({
      databaseName: "extgen bob test",
      key: "test",
      clientId: "bob",
    });

    const [bobKp, ] = await bob.clientKeypackages(1);

    const conversationId = encoder.encode("testConversation");

    await alice.createConversation(conversationId);

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
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      databaseName: "get client public key",
      key: "test",
      clientId: "test",
    });

    const len = (await cc.clientPublicKey()).length;
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
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      databaseName: "get client keypackages",
      key: "test",
      clientId: "test",
    });

    const kps = await cc.clientKeypackages(20);
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
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init({
      databaseName: "encrypt message",
      key: "test",
      clientId: "test",
    });

    const encoder = new TextEncoder();

    const conversationId = encoder.encode("testConversation");

    await cc.createConversation(conversationId);

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

  const client1Config = {
    databaseName: "roundtrip message test 1",
    key: "test",
    clientId: "test",
  };

  const client2Config = {
    databaseName: "roundtrip message test 2",
    key: "test2",
    clientId: "test2",
  };

  let kp = await page2.evaluate(async (config) => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc2 = await CoreCrypto.init(config);

    const [kp] = await cc2.clientKeypackages(1);
    await cc2.close();
    return kp;
  }, client2Config);

  kp = Uint8Array.from(Object.values(kp));

  let [welcome, message] = await page.evaluate(async (kp, messageText, conversationId, client1Config, client2Config) => {
    const { CoreCrypto } = await import("./corecrypto.js");

    const cc = await CoreCrypto.init(client1Config);

    const encoder = new TextEncoder();

    const conversationIdBuffer = encoder.encode(conversationId);

    await cc.createConversation(conversationIdBuffer);

    const memberAdded = await cc.addClientsToConversation(conversationIdBuffer, [
      { id: encoder.encode(client2Config.clientId), kp: Uint8Array.from(Object.values(kp)) },
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
  }, kp, messageText, conversationId, client1Config, client2Config);

  welcome.welcome = Uint8Array.from(welcome.welcome);
  welcome.commit = Uint8Array.from(welcome.commit);
  welcome.publicGroupState = Uint8Array.from(welcome.publicGroupState);

  message = Uint8Array.from(Object.values(message));

  const isMessageIdentical = await page2.evaluate(async (welcome, message, messageText, conversationId, config) => {
    const welcomeMessage = Uint8Array.from(Object.values(welcome));
    const encryptedMessage = Uint8Array.from(Object.values(message));
    const { CoreCrypto } = await import("./corecrypto.js");

    const encoder = new TextEncoder();

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
  }, welcome.welcome, message, messageText, conversationId, client2Config);

  expect(isMessageIdentical).toBe(true);

  await page.close();
  await page2.close();
  await ctx.close();
  await ctx2.close();
}, 20000);

test("ext commits|proposals & callbacks", async () => {
  const [ctx, page] = await initBrowser();

  const callbacksResults = await page.evaluate(async () => {
    const { CoreCrypto, ExternalProposalType } = await import("./corecrypto.js");

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

    const client1Config = {
      databaseName: "test init",
      key: "test",
      clientId: "test",
    };

    const client2Config = {
      databaseName: "test init2",
      key: "test",
      clientId: "test2",
    };

    const clientExtProposalConfig = {
      databaseName: "test init ext proposal",
      key: "test",
      clientId: "testExternalProposal",
    };

    const clientExtCommitConfig = {
      databaseName: "test init ext commit",
      key: "test",
      clientId: "testExternalCommit",
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
    const [cc2Kp] = await cc2.clientKeypackages(1);

    const ccExternalProposal = await CoreCrypto.init(clientExtProposalConfig);
    const ccExternalCommit = await CoreCrypto.init(clientExtCommitConfig);

    const encoder = new TextEncoder();

    const conversationId = encoder.encode("Test conversation");

    await cc.createConversation(conversationId);

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
    });

    // ! This should trigger the clientIsExistingGroupUser callback
    const somethingProposal = await cc.decryptMessage(conversationId, extProposal);

    const extProposalCommit = await cc.commitPendingProposals(conversationId);
    await cc.commitAccepted(conversationId);
    await assertEpoch(conversationId, ++theoreticalEpoch, cc);

    if (!callbacksResults.clientIsExistingGroupUser) {
      throw new Error("clientIsExistingGroupUser callback wasn't triggered");
    }

    const pgs = extProposalCommit.publicGroupState;

    const extCommit = await ccExternalCommit.joinByExternalCommit(pgs.payload);
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
    const { CoreCrypto, CoreCryptoError } = await import("./corecrypto.js");

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const client1Config = {
      databaseName: "proteus test1",
      key: "test",
    };

    const client2Config = {
      databaseName: "proteus test2",
      key: "test",
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
