import {
    ccInit,
    createConversation,
    DELIVERY_SERVICE,
    setup,
    teardown,
} from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";
import {
    ConversationId,
    type HistorySecret,
} from "@wireapp/core-crypto/native";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("history sharing", () => {
    test("enable and disable should work", async () => {
        // set up the observer. this just keeps a list of all observations.
        type ObservedHistoryClient = {
            conversationId: ConversationId;
            historySecret: HistorySecret;
        };
        class Observer {
            observations: ObservedHistoryClient[];

            constructor() {
                this.observations = [];
            }

            async historyClientCreated(
                conversationId: ConversationId,
                historySecret: HistorySecret
            ): Promise<void> {
                this.observations.push({
                    conversationId,
                    historySecret,
                });
            }
        }

        const observer = new Observer();

        const cc = await ccInit();

        // create the conversation in one transaction
        const convId = await createConversation(cc);

        // register the observer
        await cc.registerHistoryObserver(observer);

        const enabledBeforeEnabling = await cc.isHistorySharingEnabled(convId);

        // in another transaction, enable history sharing
        await cc.transaction(async (ctx) => {
            await ctx.enableHistorySharing(convId);
        });

        const enabledAfterEnabling = await cc.isHistorySharingEnabled(convId);

        const commitHasEncryptedMessage =
            (await DELIVERY_SERVICE.getLatestCommitBundle())
                .encryptedMessage !== undefined;

        const decoder = new TextDecoder();

        // we have to explicitly return non-primitives, as anything passed by reference won't make it out of
        // the browser context
        const firstIdString = decoder.decode(
            observer.observations[0]?.conversationId.copyBytes() ??
                new Uint8Array()
        );
        const convIdSerialized = decoder.decode(
            convId.copyBytes() ?? new Uint8Array()
        );
        expect(observer.observations.length).toBe(1);
        expect(enabledBeforeEnabling).toBeFalse();
        expect(enabledAfterEnabling).toBeTrue();
        expect(firstIdString).toBe(convIdSerialized);
        expect(commitHasEncryptedMessage).toBeTrue();
    });
});
