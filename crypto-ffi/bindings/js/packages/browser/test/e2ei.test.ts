import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { E2eiConversationState } from "@wireapp/core-crypto/browser";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("PKI environment", () => {
    it("should be settable after mls init", async () => {
        // Get unset pki environment
        const success = await browser.execute(async () => {
            const cc = await window.helpers.ccInit({
                withBasicCredential: false,
            });

            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            // set pki environment
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.Database.open(
                crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key.buffer)
            );
            pkiEnv = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pkiEnv);
            // We cannot compare the result of getPkiEnvironment()
            // with `pkiEnv`, due to uniffi hiding everything,
            // so just make sure it's not undefined.
            if ((await cc.getPkiEnvironment()) === undefined) return false;

            await cc.setPkiEnvironment(undefined);
            return (await cc.getPkiEnvironment()) === undefined;
        });
        await expect(success).toBe(true);
    });

    it("should be settable before mls init", async () => {
        const success = await browser.execute(async () => {
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.Database.open(
                window.crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key.buffer)
            );

            const cc = window.ccModule.CoreCrypto.new(database);
            let pkiEnv = await cc.getPkiEnvironment();

            if (pkiEnv != undefined) {
                throw new Error("Expected pkiEnv to be undefined.");
            }

            pkiEnv = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );
            await cc.setPkiEnvironment(pkiEnv);

            return (await cc.getPkiEnvironment()) != undefined;
        });
        await expect(success).toBe(true);
    });
});

describe("end to end identity", () => {
    it("should instantiate an x509 credential acquisition object", async () => {
        const acquisitionCreated = await browser.execute(async () => {
            const key = new Uint8Array(32);
            window.crypto.getRandomValues(key);
            const database = await window.ccModule.Database.open(
                crypto.randomUUID(),
                new window.ccModule.DatabaseKey(key.buffer)
            );
            const pkiEnvironment = await window.ccModule.PkiEnvironment.create(
                window.pkiEnvironmentHooks,
                database
            );

            const clientId = window.helpers.newClientId(
                "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com"
            );
            const config =
                window.ccModule.X509CredentialAcquisitionConfiguration.new({
                    acmeUrl: "acme.example.com",
                    idpUrl: "https://idp.example.com",
                    ciphersuite: window.defaultCipherSuite,
                    displayName: "Alice Smith",
                    clientId,
                    handle: "alice_wire",
                    domain: "world.com",
                    team: undefined,
                    validityPeriodSecs: BigInt(3600),
                });

            const acquisition = new window.ccModule.X509CredentialAcquisition(
                pkiEnvironment,
                config
            );

            return acquisition !== undefined;
        });

        await expect(acquisitionCreated).toBe(true);
    });

    it("should not be enabled on conversation with basic credential", async () => {
        const conversationState = await browser.execute(async () => {
            const cc = await window.helpers.ccInit();
            const conversationId = await window.helpers.createConversation(cc);
            return await cc.transaction(async (ctx) => {
                return await ctx.e2eiConversationState(conversationId);
            });
        });
        expect(conversationState).toBe(E2eiConversationState.NotEnabled);
    });

    it("identities can be queried by client id", async () => {
        const success = await browser.execute(async () => {
            const clientIdStr = window.crypto.randomUUID();
            const clientId = window.helpers.newClientId(clientIdStr);
            const cc = await window.helpers.ccInit({ clientId });
            const conversationId = await window.helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getDeviceIdentities(conversationId, [
                    clientId,
                ]);
            });

            return identities.pop()?.clientId === clientIdStr;
        });
        await expect(success).toBe(true);
    });

    it("identities can be queried by user id", async () => {
        const success = await browser.execute(async () => {
            const clientIdStr =
                "LcksJb74Tm6N12cDjFy7lQ:8e6424430d3b28be@world.com";
            const clientId = window.helpers.newClientId(clientIdStr);
            const cc = await window.helpers.ccInit({ clientId });
            const conversationId = await window.helpers.createConversation(cc);
            const identities = await cc.transaction(async (ctx) => {
                return await ctx.getUserIdentities(conversationId, [
                    "LcksJb74Tm6N12cDjFy7lQ",
                ]);
            });

            return (
                identities.values().next().value?.pop()?.clientId ===
                clientIdStr
            );
        });
        await expect(success).toBe(true);
    });
});
