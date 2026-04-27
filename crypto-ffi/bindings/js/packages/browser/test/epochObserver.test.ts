import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("epoch observer", () => {
    it("should observe new epochs", async () => {
        const { length, first_id_hex, convIdSerialized } =
            await browser.execute(async () => {
                // set up the observer. this just keeps a list of all observations.
                type ObservedEpoch = {
                    // @ts-expect-error `window` is not present when ts is checking, but is present in the browser
                    conversationId: window.ccModule.ConversationId;
                    epoch: bigint;
                };
                class Observer {
                    observations: ObservedEpoch[];
                    constructor() {
                        this.observations = [];
                    }
                    async epochChanged(
                        // @ts-expect-error `window` is not present when ts is checking, but is present in the browser
                        conversationId: window.ccModule.ConversationId,
                        epoch: bigint
                    ): Promise<void> {
                        this.observations.push({ conversationId, epoch });
                    }
                }
                const observer = new Observer();

                const cc = await window.helpers.ccInit();

                // create the conversation in one transaction
                const convId = await window.helpers.createConversation(cc);

                // register the epoch observer
                await cc.registerEpochObserver(observer);

                // in another transaction, change the epoch
                await cc.transaction(async (ctx) => {
                    await ctx.updateKeyingMaterial(convId);
                });

                // wait a bit to ensure that the observation, which we have intentionally
                // not awaited, makes it to us
                await new Promise((resolve) => setTimeout(resolve, 200)); // 200ms should be plenty

                // pass a serializable
                const first_id_hex = new TextDecoder().decode(
                    observer.observations[0]?.conversationId.copyBytes()
                );

                const convIdSerialized = new TextDecoder().decode(
                    convId.copyBytes()
                );
                return {
                    length: observer.observations.length,
                    first_id_hex,
                    convIdSerialized,
                };
            });

        await expect(length).toEqual(1);
        await expect(first_id_hex).toEqual(convIdSerialized);
    });
});
