import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database", () => {
    it("open previously created db works", async () => {
        await expect(
            browser.execute(async () => {
                const databaseName = crypto.randomUUID();
                const key = new Uint8Array(32);
                crypto.getRandomValues(key);

                await ccModule.Database.open(
                    databaseName,
                    new ccModule.DatabaseKey(key)
                );

                const db = await ccModule.Database.open(
                    databaseName,
                    new ccModule.DatabaseKey(key)
                );

                return { dbIsDefined: db !== undefined };
            })
        ).resolves.toMatchObject({ dbIsDefined: true });
    });

    it("can get the database location", async () => {
        await expect(
            browser.execute(async () => {
                const databaseName = crypto.randomUUID();
                const key = new Uint8Array(32);
                crypto.getRandomValues(key);

                const db = await ccModule.Database.open(
                    databaseName,
                    new ccModule.DatabaseKey(key)
                );

                return {
                    locationMatches: databaseName === (await db.getLocation()),
                };
            })
        ).resolves.toMatchObject({ locationMatches: true });
    });

    it("key must have correct length", async () => {
        await expect(
            browser.execute(async () => {
                new ccModule.DatabaseKey(new Uint8Array(11));
            })
        ).rejects.toThrow();
    });

    it("key update works", async () => {
        const [pubkey1, pubkey2] = await browser.execute(async () => {
            const databaseName = crypto.randomUUID();

            const keyBytes = new Uint8Array(32);
            crypto.getRandomValues(keyBytes);
            const key = new ccModule.DatabaseKey(keyBytes);

            const database = await ccModule.Database.open(databaseName, key);
            const clientId = helpers.newClientId();
            let cc = await helpers.ccInit({
                withBasicCredential: true,
                database,
                clientId,
            });

            const pubkey1 = (
                await cc.findCredentials({ clientId })
            )[0]!.publicKeyHash();

            const newKeyBytes = new Uint8Array(32);
            crypto.getRandomValues(newKeyBytes);
            const newKey = new ccModule.DatabaseKey(newKeyBytes);

            try {
                await database.updateKey(newKey);
            } catch (e) {
                console.error("updating database key caught:", e);
                console.error(JSON.stringify(e));
                throw e;
            }

            cc = await helpers.ccInit({
                withBasicCredential: false,
                database,
                clientId,
            });
            const pubkey2 = (
                await cc.findCredentials({ clientId })
            )[0]!.publicKeyHash();
            await database.close();

            return [JSON.stringify(pubkey1), JSON.stringify(pubkey2)];
        });

        expect(JSON.parse(pubkey1)).toEqual(JSON.parse(pubkey2));
    });
});
