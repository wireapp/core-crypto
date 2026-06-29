import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("logger", () => {
    it("forwards logs when registered", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } = ccModule;

            const logs: string[] = [];
            setLogger({
                log: (_level, json_msg: string, _context) => {
                    logs.push(json_msg);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Debug);
            await helpers.createConversation(cc);
            return logs;
        });

        expect(result.length).to.be.greaterThan(0);
    });

    it("can be replaced", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } = ccModule;

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
            await helpers.createConversation(cc);
            return logs;
        });

        expect(result.length).to.be.greaterThan(0);
    });

    it("doesn't forward logs below log level when registered", async () => {
        const result = await runOnPlatform(async () => {
            const cc = await helpers.ccInit();
            const { setMaxLogLevel, CoreCryptoLogLevel, setLogger } = ccModule;

            const logs: string[] = [];
            setLogger({
                log: (_level, json_msg: string, _context) => {
                    logs.push(json_msg);
                },
            });
            setMaxLogLevel(CoreCryptoLogLevel.Warn);
            await helpers.createConversation(cc);
            return logs;
        });

        expect(result.length).to.equal(0);
    });

    it("forwards logs with context key/value pairs", async () => {
        const result = await runOnPlatform(async () => {
            const alice = await helpers.ccInit();
            const bob = await helpers.ccInit();
            const conversationId = await helpers.createConversation(alice);
            await helpers.invite(alice, bob, conversationId);

            helpers.recordLogs();

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

            return recordedLogs;
        });

        const proteusErrorLog = result.find(
            (element) => element.message === "Application message"
        )!.context;

        expect(JSON.parse(proteusErrorLog)).to.have.keys(
            "group_id",
            "sender_client_id",
            "epoch"
        );
    });

    it("forward logs with member changes", async () => {
        const logs = await runOnPlatform(async () => {
            const alice = await helpers.ccInit();
            const bob = await helpers.ccInit();
            const carolId = helpers.newClientId();
            const carol = await helpers.ccInit({ clientId: carolId });
            helpers.recordLogs();
            const conversationId = await helpers.createConversation(alice);
            await helpers.invite(alice, bob, conversationId);
            await helpers.invite(alice, carol, conversationId);
            await helpers.consumeLastestCommit(bob, conversationId);
            await helpers.remove(alice, carolId, conversationId);
            await helpers.consumeLastestCommit(bob, conversationId);
            return recordedLogs;
        });

        const epochChangedContext1 = logs.find(
            (element) => element.message === "Epoch advanced"
        )!.context;
        const epochChangedContext2 = logs.findLast(
            (element) => element.message === "Epoch advanced"
        )!.context;

        const parsed1 = JSON.parse(epochChangedContext1);
        expect(parsed1).to.have.keys(
            "removed",
            "group_id",
            "epoch",
            "added",
            "proposals"
        );
        expect(parsed1.added).to.include("Member");
        expect(parsed1.removed).to.equal("[]");

        const parsed2 = JSON.parse(epochChangedContext2);
        expect(parsed2).to.have.keys(
            "removed",
            "group_id",
            "epoch",
            "added",
            "proposals"
        );
        expect(parsed2.added).to.equal("[]");
        expect(parsed2.removed).to.include("Member");
    });
});
