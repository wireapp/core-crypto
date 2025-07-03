import { browser, expect } from "@wdio/globals";
import { ALICE_ID, ccInit, CONV_ID, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("epoch observer", () => {
    it("should observe new epochs", async () => {
        await ccInit(ALICE_ID);
        const { length, first_id_hex } = await browser.execute(
            async (clientName, conv_id_str) => {
                const conv_id = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conv_id_str)
                );

                // set up the observer. this just keeps a list of all observations.
                type ObservedEpoch = {
                    // @ts-expect-error `window` is not present when ts is checking, but is present in the browser
                    conversationId: window.ccModule.ConversationId;
                    epoch: number;
                };
                class Observer {
                    observations: ObservedEpoch[];
                    constructor() {
                        this.observations = [];
                    }
                    async epochChanged(
                        // @ts-expect-error `window` is not present when ts is checking, but is present in the browser
                        conversationId: window.ccModule.ConversationId,
                        epoch: number
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

                // we have to explicitly return non-primitives, as anything passed by reference won't make it out of the browser context
                const first_id_hex = Array.from(
                    observer.observations[0]?.conversationId.copyBytes() ??
                    new Uint8Array(),
                    (byte: number) => {
                        return ("0" + (byte & 0xff).toString(16)).slice(-2);
                    }
                ).join("");
                return { length: observer.observations.length, first_id_hex };
            },
            ALICE_ID,
            CONV_ID
        );

        const expect_conversation_id = new TextEncoder().encode(CONV_ID);
        const expect_conversation_id_hex = Array.from(
            expect_conversation_id,
            (byte) => {
                return ("0" + (byte & 0xff).toString(16)).slice(-2);
            }
        ).join("");

        expect(length).toEqual(1);
        expect(first_id_hex).toEqual(expect_conversation_id_hex);
    });
});
