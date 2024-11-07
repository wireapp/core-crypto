import puppeteer from "puppeteer";

import { rm } from "node:fs/promises";
import { expect, test, beforeAll, afterAll } from "bun:test";

import { exec } from "child_process";

let server;
let browser;

beforeAll(async () => {
    await Bun.write(
        "../platforms/web/index.html",
        Bun.file(import.meta.dir + "/index.html")
    );

    server = Bun.serve({
        port: 3000,
        hostname: "127.0.0.1",
        fetch(req) {
            const url = new URL(req.url);
            let filename = url.pathname;

            if (url.pathname === "/") {
                filename = "/index.html";
            } else if (url.pathname === "/favicon.ico") {
                return new Response("Not Found", { status: 404 });
            }

            const filePath = Bun.resolveSync(
                `../platforms/web${filename}`,
                process.cwd()
            );
            const file = Bun.file(filePath);
            if (file.size === 0) {
                // Not exists
                return new Response("Not Found", { status: 404 });
            }

            return new Response(file);
        },
    });
});

afterAll(async () => {
    server.stop();
    await rm("../platforms/web/index.html");
});

async function initBrowser(args = { captureLogs: true }) {
    if (!browser) {
        browser = await puppeteer.launch({ headless: "new" });
    }
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    if (args.captureLogs) {
        page.on("console", (msg) => {
            const msgText = msg.text();
            if (msgText.includes("404 (Not Found)")) {
                return;
            }

            console.log("PAGE LOG:", msgText);
        });
    }

    await page.goto("http://localhost:3000");
    return [context, page];
}

async function execAsync(command, options = {}) {
    return new Promise((resolve, reject) =>
        exec(command, options, (err, stdout, stderr) => {
            if (err) {
                err.stderr = stderr;
                err.stdout = stdout;
                return reject(err);
            }

            resolve([stdout, stderr]);
        })
    );
}

test("tsc import of package", async () => {
    const args = [
        "--moduleResolution node",
        "-t es2020",
        "-m es2020",
        "--lib es2020",
        "--noEmit",
    ];

    try {
        await execAsync(
            `bunx typescript@latest ${args.join(" ")} ./bindings/js/test/tsc-import-test.ts`
        );
    } catch (cause) {
        throw new Error(
            `Couldn't build @wireapp/core-crypto import.

      tsc output:
      ${cause.stdout}
      ${cause.stderr}`,
            {
                cause,
            }
        );
    }
}, 10000);

test("init", async () => {
    const [ctx, page] = await initBrowser();

    const version = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        await CoreCrypto.init({
            databaseName: "test init",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        return CoreCrypto.version();
    });

    expect(version).toEqual(expect.anything());

    await page.close();
    await ctx.close();
}, 10000);

test("can use groupInfo enums", async () => {
    const [ctx, page] = await initBrowser();

    const [GroupInfoEncryptionType, RatchetTreeType, CredentialType] =
        await page.evaluate(async () => {
            const {
                CoreCrypto,
                Ciphersuite,
                CredentialType,
                GroupInfoEncryptionType,
                RatchetTreeType,
            } = await import("./corecrypto.js");

            window.GroupInfoEncryptionType = GroupInfoEncryptionType;
            window.RatchetTreeType = RatchetTreeType;
            window.CoreCrypto = CoreCrypto;
            window.Ciphersuite = Ciphersuite;
            window.CredentialType = CredentialType;

            return [GroupInfoEncryptionType, RatchetTreeType, CredentialType];
        });

    expect(GroupInfoEncryptionType.Plaintext).toBe(0x01);
    expect(GroupInfoEncryptionType.JweEncrypted).toBe(0x02);
    expect(
        await page.evaluate(() => window.GroupInfoEncryptionType.Plaintext)
    ).toBe(0x01);
    expect(
        await page.evaluate(() => window.GroupInfoEncryptionType.JweEncrypted)
    ).toBe(0x02);
    expect(CredentialType.Basic).toBe(0x01);
    expect(CredentialType.X509).toBe(0x02);
    expect(await page.evaluate(() => window.CredentialType.Basic)).toBe(0x01);
    expect(await page.evaluate(() => window.CredentialType.X509)).toBe(0x02);
    expect(RatchetTreeType.Full).toBe(0x01);
    expect(RatchetTreeType.Delta).toBe(0x02);
    expect(RatchetTreeType.ByRef).toBe(0x03);
    expect(await page.evaluate(() => window.RatchetTreeType.Full)).toBe(0x01);
    expect(await page.evaluate(() => window.RatchetTreeType.Delta)).toBe(0x02);
    expect(await page.evaluate(() => window.RatchetTreeType.ByRef)).toBe(0x03);

    const pgs = await page.evaluate(async () => {
        const ciphersuite =
            window.Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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

        const [kp] = await cc2.clientKeypackages(
            ciphersuite,
            window.CredentialType.Basic,
            1
        );

        const encoder = new TextEncoder();
        const conversationId = encoder.encode("testConversation");

        await cc.createConversation(
            conversationId,
            window.CredentialType.Basic
        );

        const { groupInfo: groupInfo } = await cc.addClientsToConversation(
            conversationId,
            [kp]
        );

        return groupInfo;
    });

    expect(pgs.encryptionType).toBe(0x01);
    expect(pgs.encryptionType).toBe(GroupInfoEncryptionType.Plaintext);
    expect(pgs.ratchetTreeType).toBe(0x01);
    expect(pgs.ratchetTreeType).toBe(RatchetTreeType.Full);

    await page.close();
    await ctx.close();
});

test("Using invalid context throws error", async () => {
    const [ctx, page] = await initBrowser();

    const error = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );
        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        const client2Config = {
            databaseName: "test",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        };

        const cc = await CoreCrypto.init(client2Config);

        let context;
        await cc.transaction((ctx) => {
            context = ctx;
        });

        let error;

        try {
            // Attempt to perform an operation on an invalid context
            await context.clientKeypackages(
                ciphersuite,
                CredentialType.Basic,
                1
            );
        } catch (e) {
            error = e;
        }

        return error;
    });

    expect(error.rustStackTrace).toBe("CryptoError(InvalidContext)");

    await page.close();
    await ctx.close();
});

test("JS Error is propagated by transaction", async () => {
    const [ctx, page] = await initBrowser();
    await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");
        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        const client2Config = {
            databaseName: "test",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        };

        const cc = await CoreCrypto.init(client2Config);

        const expectedError = new Error("Message of expected error", {
            cause: "This is expected!",
        });
        let thrownError;
        try {
            await cc.transaction(() => {
                throw expectedError;
            });
        } catch (e) {
            thrownError = e;
        }

        if (!(thrownError instanceof Error)) {
            throw new Error("Error wasn't thrown");
        }
        if (
            !thrownError.message ||
            thrownError.message !== expectedError.message
        ) {
            throw new Error(
                "Error message is not equal to expected error message"
            );
        }
    });

    await page.close();
    await ctx.close();
});

test("can import ciphersuite enum", async () => {
    const [ctx, page] = await initBrowser();

    const Ciphersuite = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

        window.cc = await CoreCrypto.init({
            databaseName: "test ciphersuite",
            key: "test",
            ciphersuites: [
                Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            ],
            clientId: "test",
        });

        window.ciphersuite = Ciphersuite;
        return Ciphersuite;
    });

    expect(Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).toBe(
        0x0001
    );
    expect(Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256).toBe(0x0002);
    expect(
        Ciphersuite.MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    ).toBe(0x0003);
    expect(Ciphersuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448).toBe(0x0004);
    expect(Ciphersuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521).toBe(0x0005);
    expect(Ciphersuite.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448).toBe(
        0x0006
    );
    expect(Ciphersuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384).toBe(0x0007);

    expect(
        await page.evaluate(
            () =>
                window.ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        )
    ).toBe(0x0001);
    expect(
        await page.evaluate(
            () => window.ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        )
    ).toBe(0x0002);
    expect(
        await page.evaluate(
            () =>
                window.ciphersuite
                    .MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        )
    ).toBe(0x0003);
    expect(
        await page.evaluate(
            () => window.ciphersuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
        )
    ).toBe(0x0004);
    expect(
        await page.evaluate(
            () => window.ciphersuite.MLS_256_DHKEMP521_AES256GCM_SHA512_P521
        )
    ).toBe(0x0005);
    expect(
        await page.evaluate(
            () =>
                window.ciphersuite
                    .MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448
        )
    ).toBe(0x0006);
    expect(
        await page.evaluate(
            () => window.ciphersuite.MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        )
    ).toBe(0x0007);

    await page.close();
    await ctx.close();
});

test("external entropy", async () => {
    const [ctx, page] = await initBrowser();

    // Test vectors 1 and 2 from
    // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04
    const vector1 = Uint32Array.from([
        0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0,
        0xccef36a8, 0xc70d778b, 0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
        0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
    ]);
    const vector2 = Uint32Array.from([
        0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348,
        0x3e53c612, 0xed7aee32, 0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874,
        0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b,
    ]);

    let [produced1, produced2] = await page.evaluate(
        async (expected1Length, expected2Length) => {
            const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

            // Null byte seed
            const seed = new Uint8Array(32);

            const ciphersuite =
                Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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
        },
        vector1.length * vector1.BYTES_PER_ELEMENT,
        vector2.length * vector2.BYTES_PER_ELEMENT
    );

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
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const alice = await CoreCrypto.deferredInit({
            databaseName: "extgen alice test",
            key: "test",
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

        const [bobKp] = await bob.clientKeypackages(
            ciphersuite,
            credentialType,
            1
        );

        const conversationId = encoder.encode("testConversation");

        await alice.createConversation(conversationId, credentialType);

        const memberAdded = await alice.addClientsToConversation(
            conversationId,
            [bobKp]
        );

        if (!memberAdded) {
            throw new Error("no welcome message was generated");
        }

        await alice.commitAccepted(conversationId);

        const welcome = await bob.processWelcomeMessage(memberAdded.welcome);
        const welcomeConversationId = welcome.id;

        if (
            !conversationId.every((val, i) => val === welcomeConversationId[i])
        ) {
            throw new Error(
                `conversationId mismatch, got ${welcomeConversationId}, expected ${conversationId}`
            );
        }

        const messageText = "Hello world!";
        const messageBuffer = encoder.encode(messageText);

        const encryptedMessage = await alice.encryptMessage(
            conversationId,
            messageBuffer
        );

        const decryptedMessage = await bob.decryptMessage(
            welcomeConversationId,
            encryptedMessage
        );

        if (!decryptedMessage.message) {
            return new Error(
                "alice -> bob decrypted message isn't an application message"
            );
        }

        if (
            !decryptedMessage.message.every(
                (val, i) => val === messageBuffer[i]
            )
        ) {
            throw new Error(
                "alice -> bob message differs from bob's point of view"
            );
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
            return new Error(
                "bob -> alice decrypted message isn't an application message"
            );
        }

        if (
            !aliceDecryptedMessage.message.every(
                (val, i) => val === messageBuffer[i]
            )
        ) {
            throw new Error(
                "bob -> alice message differs from alice's point of view"
            );
        }
    });

    await page.close();
    await ctx.close();
});

test("get client public key", async () => {
    const [ctx, page] = await initBrowser();

    const pkLength = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const cc = await CoreCrypto.init({
            databaseName: "get client public key",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        const len = (
            await cc.clientPublicKey(ciphersuite, CredentialType.Basic)
        ).length;
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
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "get client keypackages",
            key: "test",
            clientId: "test",
            ciphersuites: [ciphersuite],
        });

        const kps = await cc.clientKeypackages(ciphersuite, credentialType, 20);
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

    const [msgLen, cs, Ciphersuite] = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite = Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "encrypt message",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        const encoder = new TextEncoder();

        const conversationId = encoder.encode("testConversation");

        await cc.createConversation(conversationId, credentialType, {
            ciphersuite,
        });
        const cs = await cc.conversationCiphersuite(conversationId);

        const encryptedMessage = await cc.encryptMessage(
            conversationId,
            encoder.encode("Hello World!")
        );

        const len = encryptedMessage.length;

        await cc.wipe();

        return [len, cs, Ciphersuite];
    });

    expect(msgLen).toBeGreaterThan(0);
    expect(cs).toEqual(Ciphersuite.MLS_128_DHKEMP256_AES128GCM_SHA256_P256);

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
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const config = {
            databaseName: "roundtrip message test 2",
            key: "test2",
            clientId: clientId,
            ciphersuites: [ciphersuite],
        };

        const cc2 = await CoreCrypto.init(config);

        const [kp] = await cc2.clientKeypackages(
            ciphersuite,
            credentialType,
            1
        );
        await cc2.close();
        return kp;
    }, clientId2);

    kp = Uint8Array.from(Object.values(kp));

    let [welcome, message] = await page.evaluate(
        async (kp, messageText, conversationId) => {
            const { CoreCrypto, Ciphersuite, CredentialType } = await import(
                "./corecrypto.js"
            );

            const ciphersuite =
                Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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

            const memberAdded = await cc.addClientsToConversation(
                conversationIdBuffer,
                [Uint8Array.from(Object.values(kp))]
            );

            await cc.commitAccepted(conversationIdBuffer);

            if (!memberAdded) {
                throw new Error("no welcome message was generated");
            }

            const message = await cc.encryptMessage(
                conversationIdBuffer,
                encoder.encode(messageText)
            );

            return [memberAdded, message];
        },
        kp,
        messageText,
        conversationId,
        clientId2
    );

    welcome.welcome = Uint8Array.from(welcome.welcome);
    welcome.commit = Uint8Array.from(welcome.commit);
    welcome.groupInfo = Uint8Array.from(welcome.groupInfo);

    message = Uint8Array.from(Object.values(message));

    const isMessageIdentical = await page2.evaluate(
        async (welcome, message, messageText, conversationId, clientId) => {
            const welcomeMessage = Uint8Array.from(Object.values(welcome));
            const encryptedMessage = Uint8Array.from(Object.values(message));
            const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

            const encoder = new TextEncoder();

            const ciphersuite =
                Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
            const config = {
                databaseName: "roundtrip message test 2",
                key: "test2",
                clientId: clientId,
                ciphersuites: [ciphersuite],
            };
            const cc2 = await CoreCrypto.init(config);

            const messageBuffer = encoder.encode(messageText);

            const conversationIdBuffer = encoder.encode(conversationId);

            const welcome2 = await cc2.processWelcomeMessage(welcomeMessage);
            const welcomeConversationId = welcome2.id;
            if (
                !conversationIdBuffer.every(
                    (val, i) => val === welcomeConversationId[i]
                )
            ) {
                throw new Error(
                    `conversationId mismatch, got ${welcomeConversationId}, expected ${conversationIdBuffer}`
                );
            }

            const decryptedMessage = await cc2.decryptMessage(
                welcomeConversationId,
                encryptedMessage
            );

            if (!decryptedMessage.message) {
                return false;
            }

            return decryptedMessage.message.every(
                (val, i) => val === messageBuffer[i]
            );
        },
        welcome.welcome,
        message,
        messageText,
        conversationId,
        clientId2
    );

    expect(isMessageIdentical).toBe(true);

    await page.close();
    await page2.close();
    await ctx.close();
    await ctx2.close();
}, 20000);

test("callbacks default to false when not async", async () => {
    const [, page] = await initBrowser({ captureLogs: false });

    const result = await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite, CredentialType } = await import(
            "./corecrypto.js"
        );

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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
            authorize() {
                return true;
            },
            userAuthorize() {
                return true;
            },
            clientIsExistingGroupUser() {
                return true;
            },
        };

        const cc = await CoreCrypto.init(client1Config);

        await cc.registerCallbacks(callbacks);

        const cc2 = await CoreCrypto.init(client2Config);
        const [cc2Kp] = await cc2.clientKeypackages(
            ciphersuite,
            credentialType,
            1
        );

        const encoder = new TextEncoder();

        const conversationId = encoder.encode("Test conversation");

        await cc.createConversation(conversationId, credentialType);

        try {
            await cc.addClientsToConversation(conversationId, [cc2Kp]);
        } catch (e) {
            return false;
        }

        return true;
    });

    expect(result).toBe(false);
});

test("ext commits|proposals & callbacks", async () => {
    const [ctx, page] = await initBrowser();

    await page.evaluate(async () => {
        const {
            CoreCrypto,
            Ciphersuite,
            CredentialType,
            ExternalProposalType,
        } = await import("./corecrypto.js");

        let theoreticalEpoch = 0;

        const assertEpoch = async (conversationId, expected, client) => {
            const got = await client.conversationEpoch(conversationId);
            if (parseInt(expected, 10) !== parseInt(got, 10)) {
                throw new Error(
                    `Epoch mismatch, expected ${expected}; got ${got}`
                );
            }
        };

        const callbacksResults = {
            authorize: false,
            userAuthorize: false,
            clientIsExistingGroupUser: false,
        };

        const credentialType = CredentialType.Basic;
        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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
            async authorize() {
                callbacksResults.authorize = true;
                return true;
            },
            async userAuthorize() {
                callbacksResults.userAuthorize = true;
                return true;
            },
            async clientIsExistingGroupUser() {
                callbacksResults.clientIsExistingGroupUser = true;
                return true;
            },
        };

        const cc = await CoreCrypto.init(client1Config);

        await cc.registerCallbacks(callbacks);

        const cc2 = await CoreCrypto.init(client2Config);
        const [cc2Kp] = await cc2.clientKeypackages(
            ciphersuite,
            credentialType,
            1
        );

        const ccExternalProposal = await CoreCrypto.init(
            clientExtProposalConfig
        );
        await CoreCrypto.init(clientExtCommitConfig);

        const encoder = new TextEncoder();

        const conversationId = encoder.encode("Test conversation");

        await cc.createConversation(conversationId, credentialType);

        // ! This should trigger the authorize callback
        const creationMessage = await cc.addClientsToConversation(
            conversationId,
            [cc2Kp]
        );

        await cc.commitAccepted(conversationId);
        await assertEpoch(conversationId, ++theoreticalEpoch, cc);

        if (!callbacksResults.authorize) {
            throw new Error("authorize callback wasn't triggered");
        }

        await cc2.processWelcomeMessage(creationMessage.welcome);

        const extProposal = await ccExternalProposal.newExternalProposal(
            ExternalProposalType.Add,
            {
                conversationId,
                // ? Be careful; If you change anything above the epoch might change because right now it's a guesswork
                // ? Normally, clients should obtain the epoch *somehow*, usually from the MLS DS, but we just guess that since we only added
                // ? one client, the epoch should only have moved from 0 (initial state) to 1 (added 1 client -> committed)
                epoch: theoreticalEpoch,
                ciphersuite: ciphersuite,
                credentialType: credentialType,
            }
        );

        // ! This should trigger the clientIsExistingGroupUser callback
        await cc.decryptMessage(conversationId, extProposal);

        await cc.commitPendingProposals(conversationId);
        await cc.commitAccepted(conversationId);
        await assertEpoch(conversationId, ++theoreticalEpoch, cc);

        if (!callbacksResults.clientIsExistingGroupUser) {
            throw new Error(
                "clientIsExistingGroupUser callback wasn't triggered"
            );
        }

        /* TODO: this test cannot work anymore since this 'groupInfo' is wrapped in a MlsMessage and 'joinByExternalCommit'
            expects a raw GroupInfo. We don't have the required methods here to unwrap the MlsMessage.
            Tracking issue: WPB-9583
        */
        /*const extCommit = await ccExternalCommit.joinByExternalCommit(groupInfo.payload, credentialType);
        // const groupInfo = extProposalCommit.groupInfo;
        // ! This should trigger the userAuthorize callback
        const somethingCommit = cc.decryptMessage(conversationId, extCommit.commit);

        await cc.commitAccepted(conversationId);
        await assertEpoch(conversationId, ++theoreticalEpoch, cc);

        await ccExternalCommit.mergePendingGroupFromExternalCommit(conversationId);

        if (!callbacksResults.userAuthorize) {
          throw new Error("userAuthorize callback wasn't triggered");
        }*/

        return callbacksResults;
    });

    // expect(callbacksResults.authorize).toBe(true);
    // expect(callbacksResults.clientIsExistingGroupUser).toBe(true);
    // expect(callbacksResults.userAuthorize).toBe(true);

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
            proteusErrorCode: 22,
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
        } catch (e) {
            if ((!e) instanceof CoreCryptoError) {
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
        const { CoreCrypto, Ciphersuite, CoreCryptoError } = await import(
            "./corecrypto.js"
        );

        const encoder = new TextEncoder();
        const decoder = new TextDecoder();

        Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
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
            throw new Error(
                `Last resort Prekey ID differs from expected ${u16MAX}, got ${lrPkId}`
            );
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
        const aliceBobMessage = await alice.proteusEncrypt(
            "ab",
            encoder.encode(message)
        );

        const decrypted = decoder.decode(
            await bob.proteusSessionFromMessage("ba", aliceBobMessage)
        );

        if (decrypted !== message) {
            throw new Error(
                "Message decrypted by bob doesn't match message sent by alice"
            );
        }

        let proteusErrCode = 0;

        proteusErrCode = await bob.proteusLastErrorCode();
        if (proteusErrCode !== 0) {
            throw new Error(
                `bob has encountered an unlikely error [code ${proteusErrCode}`
            );
        }

        try {
            await bob.proteusSessionFromMessage("ba", aliceBobMessage);
            throw new TypeError(
                "Error not thrown when CoreCryptoError[proteus error 101] should be triggered, something is wrong"
            );
        } catch (e) {
            if (e instanceof CoreCryptoError) {
                const errorCode = e.proteusErrorCode;
                if (errorCode !== 101) {
                    throw new TypeError(
                        `CoreCryptoError has been thrown, but the code isn't correct. Expected 101, got ${errorCode}`
                    );
                }

                proteusErrCode = await bob.proteusLastErrorCode();
                if (proteusErrCode !== 101) {
                    throw new TypeError(
                        `The \`proteusLastErrorCode()\` method isn't consistent with the code returned. Expected 101, got ${proteusErrCode}`
                    );
                }

                return null;
            } else if (e instanceof TypeError) {
                throw e;
            } else {
                throw new Error(
                    `Unknown error type\nCause[${typeof e}]:\n${e}`,
                    { cause: e }
                );
            }
        }
    });

    await page.close();
    await ctx.close();
});

test("end-to-end-identity", async () => {
    const [ctx, page] = await initBrowser();

    await page.evaluate(async () => {
        const { CoreCrypto, Ciphersuite } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const cc = await CoreCrypto.deferredInit({
            databaseName: "e2ei test",
            key: "test",
        });

        const encoder = new TextEncoder();
        const jsonToByteArray = (json) =>
            encoder.encode(JSON.stringify(json, null, 0));

        const clientId =
            "b7ac11a4-8f01-4527-af88-1c30885a7931:4959bc6ab12f2846@wire.com";
        const displayName = "Alice Smith";
        const handle = "alice_wire";
        const expirySec = 90 * 24 * 3600;

        let enrollment = await cc.e2eiNewEnrollment(
            clientId,
            displayName,
            handle,
            expirySec,
            ciphersuite
        );

        const directoryResp = {
            newNonce: "https://example.com/acme/new-nonce",
            newAccount: "https://example.com/acme/new-account",
            newOrder: "https://example.com/acme/new-order",
            revokeCert: "https://example.com/acme/revoke-cert",
        };
        await enrollment.directoryResponse(jsonToByteArray(directoryResp));

        const previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
        await enrollment.newAccountRequest(previousNonce);

        const accountResp = {
            status: "valid",
            orders: "https://example.com/acme/acct/evOfKhNU60wg/orders",
        };
        await enrollment.newAccountResponse(jsonToByteArray(accountResp));

        await enrollment.newOrderRequest(previousNonce);

        const newOrderResp = {
            status: "pending",
            expires: "2037-01-05T14:09:07.99Z",
            notBefore: "2016-01-01T00:00:00Z",
            notAfter: "2037-01-08T00:00:00Z",
            identifiers: [
                {
                    type: "wireapp-user",
                    value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
                {
                    type: "wireapp-device",
                    value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
            ],
            authorizations: [
                "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
            ],
            finalize: "https://example.com/acme/order/TOlocE8rfgo/finalize",
        };
        await enrollment.newOrderResponse(jsonToByteArray(newOrderResp));

        const userAuthzUrl =
            "https://example.com/acme/wire-acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL";
        await enrollment.newAuthzRequest(userAuthzUrl, previousNonce);

        const userAuthzResp = {
            status: "pending",
            expires: "2037-01-02T14:09:30Z",
            identifier: {
                type: "wireapp-user",
                value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
            },
            challenges: [
                {
                    type: "wire-oidc-01",
                    url: "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                    status: "pending",
                    token: "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                    target: "https://dex/dex",
                },
            ],
        };
        await enrollment.newAuthzResponse(jsonToByteArray(userAuthzResp));

        const deviceAuthzUrl =
            "https://example.com/acme/wire-acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz";
        await enrollment.newAuthzRequest(deviceAuthzUrl, previousNonce);

        const deviceAuthzResp = {
            status: "pending",
            expires: "2037-01-02T14:09:30Z",
            identifier: {
                type: "wireapp-device",
                value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
            },
            challenges: [
                {
                    type: "wire-dpop-01",
                    url: "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                    status: "pending",
                    token: "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                    target: "https://wire.com/clients/4959bc6ab12f2846/access-token",
                },
            ],
        };
        await enrollment.newAuthzResponse(jsonToByteArray(deviceAuthzResp));

        const backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
        const dpopTokenExpirySecs = 3600;
        await enrollment.createDpopToken(dpopTokenExpirySecs, backendNonce);

        const accessToken =
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ";
        await enrollment.newDpopChallengeRequest(accessToken, previousNonce);
        const dpopChallengeResp = {
            type: "wire-dpop-01",
            url: "https://example.com/acme/chall/prV_B7yEyA4",
            status: "valid",
            token: "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
            target: "http://example.com/target",
        };
        await enrollment.newDpopChallengeResponse(
            jsonToByteArray(dpopChallengeResp)
        );

        // simulate the OAuth redirect
        let storeHandle = await cc.e2eiEnrollmentStash(enrollment);
        enrollment = await cc.e2eiEnrollmentStashPop(storeHandle);

        const idToken =
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ";
        await enrollment.newOidcChallengeRequest(idToken, previousNonce);

        const oidcChallengeResp = {
            type: "wire-oidc-01",
            url: "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
            status: "valid",
            token: "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
            target: "http://example.com/target",
        };
        await enrollment.newOidcChallengeResponse(
            jsonToByteArray(oidcChallengeResp)
        );

        const orderUrl =
            "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";
        await enrollment.checkOrderRequest(orderUrl, previousNonce);

        const checkOrderResp = {
            status: "ready",
            finalize:
                "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
            identifiers: [
                {
                    type: "wireapp-user",
                    value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
                {
                    type: "wireapp-device",
                    value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
            ],
            authorizations: [
                "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
            ],
            expires: "2032-02-10T14:59:20Z",
            notBefore: "2013-02-09T14:59:20.442908Z",
            notAfter: "2032-02-09T15:59:20.442908Z",
        };
        await enrollment.checkOrderResponse(jsonToByteArray(checkOrderResp));

        await enrollment.finalizeRequest(previousNonce);
        const finalizeResp = {
            certificate:
                "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
            status: "valid",
            finalize:
                "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
            identifiers: [
                {
                    type: "wireapp-user",
                    value: '{"name":"Alice Smith","domain":"wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
                {
                    type: "wireapp-device",
                    value: '{"name":"Alice Smith","domain":"wire.com","client-id":"wireapp://t6wRpI8BRSeviBwwiFp5MQ!4959bc6ab12f2846@wire.com","handle":"wireapp://%40alice_wire@wire.com"}',
                },
            ],
            authorizations: [
                "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz",
            ],
            expires: "2032-02-10T14:59:20Z",
            notBefore: "2013-02-09T14:59:20.442908Z",
            notAfter: "2032-02-09T15:59:20.442908Z",
        };
        await enrollment.finalizeResponse(jsonToByteArray(finalizeResp));

        await enrollment.certificateRequest(previousNonce);
    });

    await page.close();
    await ctx.close();
});

test("e2ei is conversation invalid", async () => {
    const [ctx, page] = await initBrowser();

    let [state, E2eiConversationState] = await page.evaluate(async () => {
        const {
            CoreCrypto,
            Ciphersuite,
            CredentialType,
            E2eiConversationState,
        } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "is invalid",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        const encoder = new TextEncoder();
        const conversationId = encoder.encode("invalidConversation");
        await cc.createConversation(conversationId, credentialType);

        const state = await cc.e2eiConversationState(conversationId);

        await cc.wipe();
        return [state, E2eiConversationState];
    });

    expect(state).toBe(E2eiConversationState.NotEnabled);

    await page.close();
    await ctx.close();
});

test("logs are forwarded when logger is registered", async () => {
    const [ctx, page] = await initBrowser();

    let [logs] = await page.evaluate(async () => {
        const {
            CoreCrypto,
            Ciphersuite,
            CredentialType,
            CoreCryptoLogLevel,
            initLogger,
        } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "is invalid",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        const logs = [];
        initLogger(
            {
                log: (level, json_msg) => {
                    logs.push(json_msg);
                },
            },
            CoreCryptoLogLevel.Debug
        );

        const encoder = new TextEncoder();
        const conversationId = encoder.encode("invalidConversation");
        await cc.createConversation(conversationId, credentialType);

        await cc.wipe();
        return [logs];
    });

    expect(logs.length).toBeGreaterThan(0);

    await page.close();
    await ctx.close();
});

test("logs are not forwarded when logger is registered, but log level is too high", async () => {
    const [ctx, page] = await initBrowser();

    let [logs] = await page.evaluate(async () => {
        const {
            CoreCrypto,
            Ciphersuite,
            CredentialType,
            CoreCryptoLogLevel,
            initLogger,
        } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "is invalid",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        const logs = [];
        initLogger(
            {
                log: (level, json_msg) => {
                    logs.push(json_msg);
                },
            },
            CoreCryptoLogLevel.Warn
        );

        const encoder = new TextEncoder();
        const conversationId = encoder.encode("invalidConversation");
        await cc.createConversation(conversationId, credentialType);

        await cc.wipe();
        return [logs];
    });

    expect(logs).toHaveLength(0);

    await page.close();
    await ctx.close();
});

test("errors thrown by logger are reported as errors", async () => {
    const [ctx, page] = await initBrowser();

    const consoleErrors = [];
    page.on("console", (msg) => {
        if (msg.type() == "error") {
            consoleErrors.push(msg);
        }
    });

    await page.evaluate(async () => {
        const {
            CoreCrypto,
            Ciphersuite,
            CredentialType,
            CoreCryptoLogLevel,
            initLogger,
        } = await import("./corecrypto.js");

        const ciphersuite =
            Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        const credentialType = CredentialType.Basic;
        const cc = await CoreCrypto.init({
            databaseName: "is invalid",
            key: "test",
            ciphersuites: [ciphersuite],
            clientId: "test",
        });

        initLogger(
            {
                log: () => {
                    throw Error("test error");
                },
            },
            CoreCryptoLogLevel.Debug
        );

        const encoder = new TextEncoder();
        const conversationId = encoder.encode("invalidConversation");
        await cc.createConversation(conversationId, credentialType);
        await cc.wipe();
    });

    expect(consoleErrors.length).toBeGreaterThan(0);

    // find any console error with a remote object, we expect this to be the error we have thrown.
    const consoleError = consoleErrors.find(
        (element) => element.args().length > 0
    );
    const remoteObject = consoleError.args()[0].remoteObject();
    expect(remoteObject.className).toBe("Error");
    expect(remoteObject.description).toEqual(
        expect.stringContaining("test error")
    );

    await page.close();
    await ctx.close();
});
