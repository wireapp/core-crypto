import { browser, expect } from "@wdio/globals";
import {
    ccInit,
    consumeLastestCommit,
    createConversation,
    invite,
    recordLogs,
    remove,
    retrieveLogs,
    setup,
    teardown,
} from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("logger", () => {
    type BrowserLog = {
        level: string;
        message: string;
        source: string;
        timestamp: number;
    };

    it("forwards logs when registered", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: (_level, json_msg: string, _context) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        cid,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            alice,
            convId
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("can be replaced", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: (_level, _message, _context) => {
                        throw Error("Initial logger should not be active");
                    },
                });
                setLogger({
                    log: (_level, json_msg: string, _context) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        cid,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            alice,
            convId
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("doesn't forward logs below log level when registered", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        const result = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: string[] = [];
                setLogger({
                    log: (_level, json_msg: string, _context) => {
                        logs.push(json_msg);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Warn);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        cid,
                        window.ccModule.CredentialType.Basic
                    );
                });
                return logs;
            },
            alice,
            convId
        );

        expect(result.length).toBe(0);
    });

    it("when throwing errors they're reported as errors", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        const expectedErrorMessage = "expected test error in logger test";
        await ccInit(alice);
        await browser.execute(
            async (clientName, conversationId, expectedErrorMessage) => {
                const cc = window.ensureCcDefined(clientName);
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                setLogger({
                    log: (_level, _message, _context) => {
                        throw Error(expectedErrorMessage);
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId)
                );
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        cid,
                        window.ccModule.CredentialType.Basic
                    );
                });
            },
            alice,
            convId,
            expectedErrorMessage
        );

        const logs = (await browser.getLogs("browser")) as BrowserLog[];
        const errorLogs = logs.filter((log) => {
            return log.level === "SEVERE" && log.source === "console-api";
        });

        expect(errorLogs.length).toBeGreaterThan(0);
        expect(errorLogs[0]!.message).toEqual(
            expect.stringContaining(expectedErrorMessage)
        );
    });

    it("forwards logs with context key/value pairs", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);
        await ccInit(bob);
        await invite(alice, bob, convId);
        const result = await browser.execute(
            async (aliceName, bobName, conversationId) => {
                const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                    window.ccModule;

                const logs: {
                    level: number;
                    message: string;
                    context: string;
                }[] = [];
                setLogger({
                    log: (level: number, message: string, context: string) => {
                        logs.push({
                            level: level,
                            message: message,
                            context: context,
                        });
                    },
                });
                setMaxLogLevel(CoreCryptoLogLevel.Debug);

                const alice = window.ensureCcDefined(aliceName);
                const bob = window.ensureCcDefined(bobName);
                const encoder = new TextEncoder();
                const messageText = "Hello world!";
                const cid = new window.ccModule.ConversationId(
                    encoder.encode(conversationId)
                );
                const messageBytes = encoder.encode(messageText);

                const encryptedMessage = await alice.transaction(
                    async (ctx) => await ctx.encryptMessage(cid, messageBytes)
                );

                await bob.transaction(
                    async (ctx) =>
                        await ctx.decryptMessage(cid, encryptedMessage)
                );

                return logs;
            },
            alice,
            bob,
            convId
        );

        const proteusErrorLog = result.find(
            (element) => element.message === "Application message"
        )!.context;

        expect(JSON.parse(proteusErrorLog)).toMatchObject({
            group_id: expect.anything(),
            sender_client_id: expect.anything(),
            epoch: expect.anything(),
        });
    });

    it("forward logs with member changes", async () => {
        const alice = crypto.randomUUID();
        const bob = crypto.randomUUID();
        const carol = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await ccInit(bob);
        await ccInit(carol);
        await recordLogs();
        await createConversation(alice, convId);
        await invite(alice, bob, convId);
        await invite(alice, carol, convId);
        await consumeLastestCommit(bob, convId);
        await remove(alice, carol, convId);
        await consumeLastestCommit(bob, convId);

        const logs = await retrieveLogs();
        const epochChangedContext1 = logs.find(
            (element) => element.message === "Epoch advanced"
        )!.context;
        const epochChangedContext2 = logs.findLast(
            (element) => element.message === "Epoch advanced"
        )!.context;

        expect(JSON.parse(epochChangedContext1)).toMatchObject({
            group_id: expect.anything(),
            epoch: expect.anything(),
            removed: "[]",
            added: expect.stringContaining("Member"),
        });
        expect(JSON.parse(epochChangedContext2)).toMatchObject({
            group_id: expect.anything(),
            epoch: expect.anything(),
            removed: expect.stringContaining("Member"),
            added: "[]",
        });
    });
});
