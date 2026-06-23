import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import {
    ConversationId,
    type HistorySecret,
} from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("history sharing", () => {
    it("enable and disable should work", async () => {
        const result = await browser.execute(async () => {
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

            const cc = await helpers.ccInit();

            // create the conversation in one transaction
            const convId = await helpers.createConversation(cc);

            // register the observer
            await cc.registerHistoryObserver(observer);

            const enabledBeforeEnabling =
                await cc.isHistorySharingEnabled(convId);

            // in another transaction, enable history sharing
            await cc.transaction(async (ctx) => {
                await ctx.enableHistorySharing(convId);
            });

            const enabledAfterEnabling =
                await cc.isHistorySharingEnabled(convId);

            const commitHasEncryptedMessage =
                (await deliveryService.getLatestCommitBundle())
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
            return {
                length: observer.observations.length,
                firstIdString,
                convIdSerialized,
                enabledBeforeEnabling,
                enabledAfterEnabling,
                commitHasEncryptedMessage,
            };
        });

        expect(result.length).toBe(1);
        expect(result.enabledBeforeEnabling).toBe(false);
        expect(result.enabledAfterEnabling).toBe(true);
        expect(result.firstIdString).toBe(result.convIdSerialized);
        expect(result.commitHasEncryptedMessage).toBe(true);
    });
});
