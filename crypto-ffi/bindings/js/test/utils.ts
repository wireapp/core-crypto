import { browser } from "@wdio/globals";
import type { local } from "webdriver";

import {
    Ciphersuite,
    CommitBundle,
    CoreCrypto,
    GroupInfoBundle,
    MlsTransport,
} from "../src/CoreCrypto.js";

type ccModuleType = typeof import("../src/CoreCrypto.js");

export const ALICE_ID = "alice";
export const BOB_ID = "bob";
export const CONV_ID = "convId";
export const SESSION_ID = "proteusSessionId";

// Logging can be adjusted via the CC_TEST_LOG_LEVEL variable:
// 0 = no logs
// 1 = browser logs
// 2 = browser logs + CoreCrypto logs
const logLevel = Number(process.env.CC_TEST_LOG_LEVEL || "0");

declare global {
    interface Window {
        ccModule: ccModuleType;
        cc: { [key: string]: CoreCrypto | undefined };
        defaultCipherSuite: Ciphersuite;
        deliveryService: DeliveryService;
        _latestCommitBundle: CommitBundle;

        // Helper functions that are used inside the browser context
        /**
         * Gets a {@link CoreCrypto} instance initialized previously via
         * {@link ccInit}.
         *
         * @param clientName The name the {@link ccInit} was called with.
         *
         * @returns {CoreCrypto} The {@link CoreCrypto} instance.
         *
         * @throws Error if no instance with the name has been initialized.
         */
        ensureCcDefined: (clientName: string) => CoreCrypto;
    }
}

interface DeliveryService extends MlsTransport {
    getLatestCommitBundle: () => Promise<CommitBundle>;
}

function logEvents(entry: local.LogEntry) {
    if (logLevel >= 1) {
        console.log(`[${entry.level}] ${entry.text}`);
    }
}

export async function setup() {
    if ((await browser.getUrl()) === "about:blank") {
        await browser.url("/");
    }

    // Forward browser log events to the console.
    browser.on("log.entryAdded", logEvents);

    await browser.execute(async (logLevel) => {
        if (window.ccModule === undefined) {
            // This is imported in the browser context, where it is fetched from the static file server,
            // but typescript tries to resolve this in the local directory.
            // @ts-expect-error TS2307: Cannot find module ./corecrypto.js or its corresponding type declarations.
            window.ccModule = await import("./corecrypto.js");

            if (logLevel >= 2) {
                window.ccModule.setLogger({
                    log: (_, json_msg: string) => {
                        console.log(json_msg);
                    },
                });
                window.ccModule.setMaxLogLevel(
                    window.ccModule.CoreCryptoLogLevel.Debug
                );
            }

            window.defaultCipherSuite =
                window.ccModule.Ciphersuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        }

        window.deliveryService = {
            async sendCommitBundle(commitBundle: CommitBundle) {
                window._latestCommitBundle = commitBundle;
                return "success";
            },
            async sendMessage() {
                return "success";
            },
            async getLatestCommitBundle() {
                return window._latestCommitBundle;
            },
        };

        window.ensureCcDefined = (clientName: string) => {
            const cc = window.cc[clientName];
            if (cc === undefined) {
                throw new Error(
                    `Client with name '${clientName}' is not initialized in the browser context.`
                );
            }
            return cc;
        };
    }, logLevel);
}

export async function teardown() {
    await browser.execute(async () => {
        function promiseForIDBRequest(tx: IDBRequest) {
            return new Promise<void>((resolve, reject) => {
                tx.onsuccess = () => resolve();
                tx.onerror = () => reject(tx.error);
            });
        }

        // Delete all core crypto instances.
        for (const ccKey in window.cc) {
            const cc = window.ensureCcDefined(ccKey);
            await cc.close();
            await promiseForIDBRequest(window.indexedDB.deleteDatabase(ccKey));
            delete window.cc[ccKey];
        }
    });
    browser.off("log.entryAdded", logEvents);
}

/**
 * Initialize a {@link CoreCrypto} instance that can be obtained inside the
 * browser context via {@link Window.ensureCcDefined}.
 *
 * @param clientName The client name used to initialize.
 *
 * @returns {Promise<void>}
 */
export async function ccInit(clientName: string): Promise<void> {
    return await browser.execute(async (clientName) => {
        const cipherSuite = window.defaultCipherSuite;
        const encoder = new TextEncoder();
        const key = new Uint8Array(32);
        window.crypto.getRandomValues(key);

        const clientConfig = {
            databaseName: clientName,
            key: new window.ccModule.DatabaseKey(key),
            wasmModule: undefined,
            ciphersuites: [cipherSuite],
            clientId: encoder.encode(clientName),
        };
        const instance = await window.ccModule.CoreCrypto.init(clientConfig);
        await instance.provideTransport(window.deliveryService);

        if (window.cc === undefined) {
            window.cc = {};
        }
        window.cc[clientName] = instance;
    }, clientName);
}

/**
 * Create a conversation on a {@link CoreCrypto} instance that has
 * been initialized before via {@link ccInit}.
 *
 * @param clientName The name the {@link CoreCrypto} instance has been
 * initialized with.
 * @param conversationId The id that the conversation will be created with.
 *
 * @returns {Promise<void>}
 *
 * @throws Error if the instance with {@link clientName} cannot be found.
 */
export async function createConversation(
    clientName: string,
    conversationId: string
): Promise<void> {
    return await browser.execute(
        async (clientName, conversationId) => {
            const cc = window.ensureCcDefined(clientName);
            const encoder = new TextEncoder();
            await cc.transaction((ctx) =>
                ctx.createConversation(
                    encoder.encode(conversationId),
                    window.ccModule.CredentialType.Basic
                )
            );
        },
        clientName,
        conversationId
    );
}

/**
 * Invite {@link client2} to a previously created conversation on the
 * instance of {@link client1} (via {@link createConversation}).
 *
 * @param client1 The name of the {@link CoreCrypto} instance on which the
 * conversation was created previously.
 * @param client2 The name of the {@link CoreCrypto} instance that will be
 * invited.
 * @param conversationId The id of the previously created conversation.
 *
 * @returns {Promise<GroupInfoBundle>} The resulting group info.
 *
 * @throws Error if {@link client1} or {@link client2} instances cannot be found.
 */
export async function invite(
    client1: string,
    client2: string,
    conversationId: string
): Promise<GroupInfoBundle> {
    return await browser.execute(
        async (client1, client2, conversationId) => {
            const cc1 = window.ensureCcDefined(client1);
            const cc2 = window.ensureCcDefined(client2);

            const [kp] = await cc2.transaction((ctx) =>
                ctx.clientKeypackages(
                    window.defaultCipherSuite,
                    window.ccModule.CredentialType.Basic,
                    1
                )
            );

            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            await cc1.transaction((ctx) =>
                ctx.addClientsToConversation(conversationIdBytes, [kp])
            );
            const { groupInfo, welcome } =
                await window.deliveryService.getLatestCommitBundle();

            await cc2.transaction((ctx) => ctx.processWelcomeMessage(welcome!));

            return groupInfo;
        },
        client1,
        client2,
        conversationId
    );
}

/**
 * Inside a previously created conversation, {@link client1} encrypts
 * {@link message}, sends it to {@link client2}, who then decrypts it.
 * This procedure is then repeated vice versa.
 *
 * @param client1 The first of the conversation.
 * @param client2 The second member of the conversation.
 * @param conversationId The id of the conversation.
 * @param message The message encrypted, sent, and decrypted once in each
 * direction.
 *
 * @returns {Promise<(string | null)[]>} A two-element list, containing the decrypted {@link message} by
 * {@link client1} and {@link client2}, in that order.
 */
export async function roundTripMessage(
    client1: string,
    client2: string,
    conversationId: string,
    message: string
): Promise<(string | null)[]> {
    const [decrypted1, decrypted2] = await browser.execute(
        async (client1, client2, conversationId, message) => {
            const cc1 = window.ensureCcDefined(client1);
            const cc2 = window.ensureCcDefined(client2);

            const encoder = new TextEncoder();
            const conversationIdBytes = encoder.encode(conversationId);
            const messageBytes = encoder.encode(message);

            const encryptedByClient1 = await cc1.transaction(async (ctx) => {
                return await ctx.encryptMessage(
                    conversationIdBytes,
                    messageBytes
                );
            });
            const decryptedByClient2 = await cc2.transaction(async (ctx) => {
                return await ctx.decryptMessage(
                    conversationIdBytes,
                    encryptedByClient1
                );
            });

            const encryptedByClient2 = await cc2.transaction(async (ctx) => {
                return await ctx.encryptMessage(
                    conversationIdBytes,
                    messageBytes
                );
            });
            const decryptedByClient1 = await cc1.transaction(async (ctx) => {
                return await ctx.decryptMessage(
                    conversationIdBytes,
                    encryptedByClient2
                );
            });

            const result1 =
                decryptedByClient1.message !== undefined
                    ? Array.from(decryptedByClient1.message)
                    : null;
            const result2 =
                decryptedByClient2.message !== undefined
                    ? Array.from(decryptedByClient2.message)
                    : null;

            return [result1, result2];
        },
        client1,
        client2,
        conversationId,
        message
    );
    const decoder = new TextDecoder();
    const decryptedMessage1 =
        decrypted1 !== null ? decoder.decode(new Uint8Array(decrypted1)) : null;
    const decryptedMessage2 =
        decrypted2 !== null ? decoder.decode(new Uint8Array(decrypted2)) : null;

    return [decryptedMessage1, decryptedMessage2];
}

/**
 * Initialize a {@link CoreCrypto} instance without initializing MLS.
 * Instead, initialize proteus.
 * It can be obtained inside the browser context via
 * {@link Window.ensureCcDefined}.
 *
 * @param clientName the client name used to initialize.
 *
 * @returns {Promise<void>}
 */
export async function proteusInit(clientName: string): Promise<void> {
    return await browser.execute(async (clientName) => {
        const encoder = new TextEncoder();
        const key = new Uint8Array(32);
        window.crypto.getRandomValues(key);

        const clientConfig = {
            databaseName: clientName,
            key: new window.ccModule.DatabaseKey(key),
            clientId: encoder.encode(clientName),
        };
        const instance =
            await window.ccModule.CoreCrypto.deferredInit(clientConfig);
        await instance.transaction((ctx) => ctx.proteusInit());

        if (window.cc === undefined) {
            window.cc = {};
        }
        window.cc[clientName] = instance;
    }, clientName);
}

/**
 * Create a proteus session on the {@link CoreCrypto} instance of
 * {@link client1}, with the prekey of {@link client2}.
 *
 * @param client1 The name of the {@link CoreCrypto} instance which will
 * create the session.
 * @param client2 The name of the {@link CoreCrypto} instance whose pre key will
 * be used.
 * @param sessionId The id of session that will be created.
 *
 * @returns {Promise<void>}
 *
 * @throws Error if {@link client1} or {@link client2} instances cannot be found.
 */
export async function newProteusSessionFromPrekey(
    client1: string,
    client2: string,
    sessionId: string
): Promise<void> {
    return await browser.execute(
        async (client1, client2, sessionId) => {
            const cc1 = window.ensureCcDefined(client1);
            const cc2 = window.ensureCcDefined(client2);

            const cc2Prekey = await cc2.transaction(async (ctx) => {
                return await ctx.proteusNewPrekey(10);
            });

            await cc1.transaction(async (ctx) => {
                return await ctx.proteusSessionFromPrekey(sessionId, cc2Prekey);
            });
        },
        client1,
        client2,
        sessionId
    );
}

/**
 * Create a proteus session on the {@link CoreCrypto} instance of
 * {@link client2}, from a message encrypted by {@link client1} in a session
 * created previously via {@link newProteusSessionFromPrekey}.
 *
 * @param client1 The name of the {@link CoreCrypto} instance which used its
 * existing session to encrypt the message.
 * @param client2 The name of the {@link CoreCrypto} instance whose session will
 * be created.
 * @param sessionId The id of session that will be created.
 * For simplicity, this must match the id of the previously created session.
 * @param message The message to encrypt and create the message from.
 *
 * @returns {Promise<string | null>} the decrypted {@link message}.
 *
 * @throws Error if {@link client1} or {@link client2} instances cannot be found.
 */
export async function newProteusSessionFromMessage(
    client1: string,
    client2: string,
    sessionId: string,
    message: string
): Promise<string | null> {
    const decrypted = await browser.execute(
        async (client1, client2, sessionId, message) => {
            const cc1 = window.ensureCcDefined(client1);
            const cc2 = window.ensureCcDefined(client2);

            const encoder = new TextEncoder();
            const messageBytes = encoder.encode(message);
            const encrypted = await cc1.transaction(async (ctx) => {
                return await ctx.proteusEncrypt(sessionId, messageBytes);
            });

            const decrypted = await cc2.transaction(async (ctx) => {
                return await ctx.proteusSessionFromMessage(
                    sessionId,
                    encrypted
                );
            });

            return Array.from(decrypted);
        },
        client1,
        client2,
        sessionId,
        message
    );
    const decoder = new TextDecoder();
    return decrypted !== null
        ? decoder.decode(new Uint8Array(decrypted))
        : null;
}
