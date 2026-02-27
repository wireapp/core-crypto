import { browser, expect } from "@wdio/globals";
import { ccInit, createConversation, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { E2eiConversationState } from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("PKI environment", () => {
    it("should be settable after mls init", async () => {
        const alice = crypto.randomUUID();
        await ccInit(alice);

        // Get unset pki environment
        const pki_env = await browser.execute(async (alice) => {
            const cc = window.ensureCcDefined(alice);
            return await cc.getPkiEnvironment();
        }, alice);

        await expect(pki_env).toBe(undefined);

        // set pki environment
        const success = await browser.execute(async (alice) => {
            const cc = window.ensureCcDefined(alice);
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.openDatabase(
                crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key.buffer)
            );
            const pki_env = await window.ccModule.createPkiEnvironment(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pki_env);
            // We cannot compare the result of getPkiEnvironment()
            // with `pki_env`, due to uniffi hiding everything,
            // so just make sure it's not undefined.
            if ((await cc.getPkiEnvironment()) === undefined) return false;

            await cc.setPkiEnvironment(undefined);
            return (await cc.getPkiEnvironment()) !== undefined;
        }, alice);
        await expect(success).toBe(true);
    });

    it("should be settable before mls init", async () => {
        const alice = crypto.randomUUID();

        const pki_env = await browser.execute(async (alice) => {
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.openDatabase(
                alice,
                new window.ccModule.DatabaseKey(key.buffer)
            );

            const cc = new window.ccModule.CoreCrypto(database);
            window.cc = new Map();
            window.cc.set(alice, cc);
            const pki_env = await cc.getPkiEnvironment();
            return pki_env;
        }, alice);

        await expect(pki_env).toBe(undefined);

        const success = await browser.execute(async (alice) => {
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.openDatabase(
                alice,
                new window.ccModule.DatabaseKey(key.buffer)
            );

            const cc = window.ensureCcDefined(alice);
            const pki_env = await window.ccModule.createPkiEnvironment(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pki_env);

            return (await cc.getPkiEnvironment()) != undefined;
        }, alice);
        await expect(success).toBe(true);
    });
});

describe("end to end identity", () => {
    it("should not be enabled on conversation with basic credential", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);
        const conversationState = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId).buffer
                );
                return await cc.newTransaction(async (ctx) => {
                    return await ctx.e2eiConversationState(cid);
                });
            },
            alice,
            convId
        );
        await expect(conversationState).toBe(E2eiConversationState.NotEnabled);
    });

    it("identities can be queried by client id", async () => {
        const alice = crypto.randomUUID();
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);
        const identities = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const encoder = new TextEncoder();
                const cid = new window.ccModule.ConversationId(
                    encoder.encode(conversationId).buffer
                );
                const identities = await cc.newTransaction(async (ctx) => {
                    return await ctx.getDeviceIdentities(cid, [
                        new window.ccModule.ClientId(
                            encoder.encode(clientName).buffer
                        ),
                    ]);
                });

                return identities.pop()?.clientId;
            },
            alice,
            convId
        );
        await expect(identities).toBe(alice);
    });

    it("identities can be queried by user id", async () => {
        const alice = "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com";
        const convId = crypto.randomUUID();
        await ccInit(alice);
        await createConversation(alice, convId);
        const identities = await browser.execute(
            async (clientName, conversationId) => {
                const cc = window.ensureCcDefined(clientName);
                const cid = new window.ccModule.ConversationId(
                    new TextEncoder().encode(conversationId).buffer
                );
                const identities = await cc.newTransaction(async (ctx) => {
                    return await ctx.getUserIdentities(cid, [
                        "LcksJb74Tm6N12cDjFy7lQ",
                    ]);
                });

                return identities.values().next().value?.pop()?.clientId;
            },
            alice,
            convId
        );
        await expect(identities).toBe(alice);
    });
});
