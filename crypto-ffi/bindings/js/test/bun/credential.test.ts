import { ccInit, randomConversationId, setup, teardown } from "./utils";
import { afterEach, test, beforeEach, describe, expect } from "bun:test";
import {
    ciphersuiteDefault,
    ClientId,
    Credential,
    CredentialType,
} from "../../src/CoreCrypto";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("credentials", () => {
    test("basic credential can be created", async () => {
        const credential = Credential.basic(
            ciphersuiteDefault(),
            new ClientId(Buffer.from("any random client id here"))
        );
        expect(credential.type()).toEqual(CredentialType.Basic);
        expect(credential.earliest_validity()).toEqual(0n);
    });

    test("credential can be saved", async () => {
        const credential = Credential.basic(
            ciphersuiteDefault(),
            new ClientId(Buffer.from("any random client id here"))
        );

        // create a CC instance and init so that we get access to the transaction interface
        // only necessary until WPB-21396
        let { cc, db } = await ccInit();

        const ref = await cc.transaction(async (_ctx) => {
            return await credential.save(db);
        });

        expect(ref).toBeDefined();
        expect(ref.type()).toEqual(CredentialType.Basic);
        // saving causes the earliest validity to be updated
        expect(ref.earliest_validity()).not.toEqual(0n);
    });

    // can't have a test for adding before initializing cc instance, because it is (currently)
    // a logical error which produces an actual error to add a credential before `mlsInit` has been called
    test("credential can be added after initializing cc instance", async () => {
        const clientId = new ClientId(Buffer.from("any random client id here"));

        const credential = Credential.basic(
            ciphersuiteDefault(),
            clientId,
        );

        let { cc, db } = await ccInit();

        const ref = await cc.transaction(async (_ctx) => {
            return await credential.save(db);
        });

        await cc.transaction(async (ctx) => {
            console.log("doing mlsInit");
            await ctx.mlsInit(clientId, [ciphersuiteDefault()])
            console.log("adding credential");
            await cc.addCredential(ref);
        });

        // now that a credential has been created, we can create conversations etc
        const conversationId = randomConversationId();
        await cc.transaction(async (ctx) => {
            await ctx.createConversation(conversationId, CredentialType.Basic);
        });
    });
});
