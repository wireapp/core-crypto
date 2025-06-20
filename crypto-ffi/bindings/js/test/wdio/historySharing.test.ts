import { browser, expect } from "@wdio/globals";
import { ALICE_ID, ccInit, CONV_ID, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import type { ConversationId, HistorySecret } from "../../src/CoreCrypto";

beforeEach(async () => {
  await setup();
});

afterEach(async () => {
  await teardown();
});

describe("history sharing", () => {
  it("enable and disable should work", async () => {
    await ccInit(ALICE_ID);
    const { length, first_id_string } = await browser.execute(
      async (clientName, conv_id_str) => {
        const conv_id = new TextEncoder().encode(conv_id_str);

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
            this.observations.push({ conversationId, historySecret });
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

        // register the observer
        await cc.registerHistoryObserver(observer);

        // in another transaction, enable history sharing
        await cc.transaction(async (ctx) => {
          await ctx.enableHistorySharing(conv_id);
        });

        // wait a bit to ensure that the observation, which we have intentionally
        // not awaited, makes it to us
        await new Promise((resolve) => setTimeout(resolve, 200)); // 200ms should be plenty

        let decoder = new TextDecoder();

        // we have to explicitly return non-primitives, as anything passed by reference won't make it out of the browser context
        const first_id_string = decoder.decode(observer.observations[0]?.conversationId ??
          new Uint8Array());
        return { length: observer.observations.length, first_id_string };
      },
      ALICE_ID,
      CONV_ID
    );

    expect(length).toEqual(1);
    expect(first_id_string).toEqual(CONV_ID);
  });
});
