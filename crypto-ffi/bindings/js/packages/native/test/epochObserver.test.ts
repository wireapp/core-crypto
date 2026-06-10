import type { ConversationId } from "@wireapp/core-crypto/native";
import { ccInit, createConversation, setup, teardown } from "./utils";
import { test, expect, afterEach, beforeEach, describe } from "bun:test";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("epoch observer", () => {
    test("should observe new epochs", async () => {
        // set up the observer. this just keeps a list of all observations.
        type ObservedEpoch = {
            conversationId: ConversationId;
            epoch: bigint;
        };
        class Observer {
            observations: ObservedEpoch[];
            constructor() {
                this.observations = [];
            }
            async epochChanged(
                conversationId: ConversationId,
                epoch: bigint
            ): Promise<void> {
                this.observations.push({ conversationId, epoch });
            }
        }
        const observer = new Observer();

        const cc = await ccInit();

        // create the conversation in one transaction
        const convId = await createConversation(cc);

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

        const convIdSerialized = new TextDecoder().decode(convId.copyBytes());

        expect(observer.observations.length).toEqual(1);
        expect(first_id_hex).toEqual(convIdSerialized);
    });
});
