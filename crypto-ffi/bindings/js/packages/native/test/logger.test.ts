import {
    ccInit,
    consumeLastestCommit,
    createConversation,
    invite,
    newClientId,
    remove,
    setup,
    teardown,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    CoreCryptoLogLevel,
    setLogger,
    setMaxLogLevel,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

/**
 * Log entry from the core crypto logger
 */
export interface LogEntry {
    level: number;
    message: string;
    context: string;
}

const RECORDED_LOGS: LogEntry[] = [];
/**
 * Records logs by setting a logger and maximum log level in the browser's context.
 * The logs are stored in a global variable `window.recordedLogs` for further retrieval.
 *
 */
function recordLogs(): void {
    setLogger({
        log: (level: number, message: string, context: string) => {
            RECORDED_LOGS.push({
                level: level,
                message: message,
                context: context,
            });
        },
    });
    setMaxLogLevel(CoreCryptoLogLevel.Debug);
}

describe("logger", () => {
    test("forwards logs when registered", async () => {
        const cc = await ccInit();
        const logs: string[] = [];
        setLogger({
            log: (_level, json_msg: string, _context) => {
                logs.push(json_msg);
            },
        });
        setMaxLogLevel(CoreCryptoLogLevel.Debug);
        await createConversation(cc);
        expect(logs.length).toBeGreaterThan(0);
    });

    test("can be replaced", async () => {
        const cc = await ccInit();

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
        await createConversation(cc);

        expect(logs.length).toBeGreaterThan(0);
    });

    test("doesn't forward logs below log level when registered", async () => {
        const cc = await ccInit();

        const logs: string[] = [];
        setLogger({
            log: (_level, json_msg: string, _context) => {
                logs.push(json_msg);
            },
        });
        setMaxLogLevel(CoreCryptoLogLevel.Warn);
        await createConversation(cc);

        expect(logs.length).toBe(0);
    });

    test("forwards logs with context key/value pairs", async () => {
        const alice = await ccInit();
        const bob = await ccInit();
        const conversationId = await createConversation(alice);
        await invite(alice, bob, conversationId);

        recordLogs();

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

        const proteusErrorLog = RECORDED_LOGS.find(
            (element) => element.message === "Application message"
        )!.context;

        expect(JSON.parse(proteusErrorLog)).toMatchObject({
            group_id: expect.anything(),
            sender_client_id: expect.anything(),
            epoch: expect.anything(),
        });
    });

    test("forward logs with member changes", async () => {
        const alice = await ccInit();
        const bob = await ccInit();
        const carolId = newClientId();
        const carol = await ccInit({ clientId: carolId });
        recordLogs();
        const conversationId = await createConversation(alice);
        await invite(alice, bob, conversationId);
        await invite(alice, carol, conversationId);
        await consumeLastestCommit(bob, conversationId);
        await remove(alice, carolId, conversationId);
        await consumeLastestCommit(bob, conversationId);

        const epochChangedContext1 = RECORDED_LOGS.find(
            (element) => element.message === "Epoch advanced"
        )!.context;
        const epochChangedContext2 = RECORDED_LOGS.findLast(
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
