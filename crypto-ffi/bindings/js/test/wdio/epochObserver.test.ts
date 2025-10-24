import { browser, expect } from "@wdio/globals";
import { ccInit, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("epoch observer", () => {
    it("should observe new epochs", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        const { length, first_id_hex } = await browser.execute(
            async (clientName, conv_id_str) => {
                const conv_id = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conv_id_str).buffer
                );

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

                const cc = window.ensureCcDefined(clientName);

                // create the conversation in one transaction
                await cc.transaction(async (ctx) => {
                    await ctx.createConversation(
                        conv_id,
                        window.ccModule.CredentialType.Basic
                    );
                });

                // register the epoch observer
                await cc.registerEpochObserver(observer);

                // in another transaction, change the epoch
                await cc.transaction(async (ctx) => {
                    await ctx.updateKeyingMaterial(conv_id);
                });

                // wait a bit to ensure that the observation, which we have intentionally
                // not awaited, makes it to us
                await new Promise((resolve) => setTimeout(resolve, 200)); // 200ms should be plenty

                // pass a serializable
                const first_id_hex = new TextDecoder().decode(
                    observer.observations[0]?.conversationId.copyBytes()
                );
                return { length: observer.observations.length, first_id_hex };
            },
            alice,
            convId
        );

        expect(length).toEqual(1);
        expect(first_id_hex).toEqual(convId);
    });
});
