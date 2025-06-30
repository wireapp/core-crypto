import { browser, expect } from "@wdio/globals";
import {
    ALICE_ID,
    BOB_ID,
    ccInit,
    CONV_ID,
    createConversation,
    invite,
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
        await ccInit(ALICE_ID);
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
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("can be replaced", async () => {
        await ccInit(ALICE_ID);
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
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBeGreaterThan(0);
    });

    it("doesn't forward logs below log level when registered", async () => {
        await ccInit(ALICE_ID);
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
            ALICE_ID,
            CONV_ID
        );

        expect(result.length).toBe(0);
    });

    it("when throwing errors they're reported as errors", async () => {
        const expectedErrorMessage = "expected test error in logger test";
        await ccInit(ALICE_ID);
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
            ALICE_ID,
            CONV_ID,
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
        await ccInit(ALICE_ID);
        await createConversation(ALICE_ID, CONV_ID);
        await ccInit(BOB_ID);
        await invite(ALICE_ID, BOB_ID, CONV_ID);
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
            ALICE_ID,
            BOB_ID,
            CONV_ID
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
});
