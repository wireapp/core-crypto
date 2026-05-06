import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
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
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                window.ccModule;

            const logs: string[] = [];
            setLogger({
                log: (_level, json_msg: string, _context) => {
                    logs.push(json_msg);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Debug);
            await window.helpers.createConversation(cc);
            return logs;
        });

        await expect(result.length).toBeGreaterThan(0);
    });

    it("can be replaced", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
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
            await window.helpers.createConversation(cc);
            return logs;
        });

        await expect(result.length).toBeGreaterThan(0);
    });

    it("doesn't forward logs below log level when registered", async () => {
        const result = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                window.ccModule;

            const logs: string[] = [];
            setLogger({
                log: (_level, json_msg: string, _context) => {
                    logs.push(json_msg);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Warn);
            await window.helpers.createConversation(cc);
            return logs;
        });

        await expect(result.length).toBe(0);
    });

    it("when throwing errors they're reported as errors", async () => {
        const expectedErrorMessage = "expected test error in logger test";
        await browser.execute(async (expectedErrorMessage) => {
            const cc = await window.helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } =
                window.ccModule;

            setLogger({
                log: (_level, _message, _context) => {
                    throw Error(expectedErrorMessage);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Debug);
            await window.helpers.createConversation(cc);
        }, expectedErrorMessage);

        const logs = (await browser.getLogs("browser")) as BrowserLog[];
        console.log(JSON.stringify(logs));
        const errorLogs = logs.filter((log) => {
            return (
                log.message.includes(expectedErrorMessage) &&
                log.source === "console-api"
            );
        });

        await expect(errorLogs.length).toBeGreaterThan(0);
        await expect(errorLogs[0]!.message).toEqual(
            expect.stringContaining(expectedErrorMessage)
        );
    });

    it("forwards logs with context key/value pairs", async () => {
        const result = await browser.execute(async () => {
            const alice = await window.helpers.ccInit();
            const bob = await window.helpers.ccInit();
            const conversationId =
                await window.helpers.createConversation(alice);
            await window.helpers.invite(alice, bob, conversationId);

            await window.helpers.recordLogs();

            const encoder = new TextEncoder();
            const messageText = "Hello world!";
            const messageBytes = encoder.encode(messageText);

            const encryptedMessage = await alice.transaction(
                async (ctx) =>
                    await ctx.encryptMessage(conversationId, messageBytes)
            );

            await bob.transaction(
                async (ctx) =>
                    await ctx.decryptMessage(conversationId, encryptedMessage)
            );

            return window.helpers.retrieveLogs();
        });

        const proteusErrorLog = result.find(
            (element) => element.message === "Application message"
        )!.context;

        await expect(JSON.parse(proteusErrorLog)).toMatchObject({
            group_id: expect.anything(),
            sender_client_id: expect.anything(),
            epoch: expect.anything(),
        });
    });

    it("forward logs with member changes", async () => {
        const logs = await browser.execute(async () => {
            const alice = await window.helpers.ccInit();
            const bob = await window.helpers.ccInit();
            const carolId = window.helpers.newClientId();
            const carol = await window.helpers.ccInit({ clientId: carolId });
            await window.helpers.recordLogs();
            const conversationId =
                await window.helpers.createConversation(alice);
            await window.helpers.invite(alice, bob, conversationId);
            await window.helpers.invite(alice, carol, conversationId);
            await window.helpers.consumeLastestCommit(bob, conversationId);
            await window.helpers.remove(alice, carolId, conversationId);
            await window.helpers.consumeLastestCommit(bob, conversationId);
            return await window.helpers.retrieveLogs();
        });

        const epochChangedContext1 = logs.find(
            (element) => element.message === "Epoch advanced"
        )!.context;
        const epochChangedContext2 = logs.findLast(
            (element) => element.message === "Epoch advanced"
        )!.context;

        await expect(JSON.parse(epochChangedContext1)).toMatchObject({
            group_id: expect.anything(),
            epoch: expect.anything(),
            removed: "[]",
            added: expect.stringContaining("Member"),
        });
        await expect(JSON.parse(epochChangedContext2)).toMatchObject({
            group_id: expect.anything(),
            epoch: expect.anything(),
            removed: expect.stringContaining("Member"),
            added: "[]",
        });
    });
});
