import { runOnPlatform, setup, teardown } from "./utils";
import { afterEach, beforeEach, describe } from "mocha";
import { expect } from "chai";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database", () => {
    it("open previously created db works", async () => {
        const result = await runOnPlatform(async () => {
            const databaseName = crypto.randomUUID();
            const key = helpers.newDatabaseKey();
            await helpers.newDatabase(databaseName, key);
            const db = await helpers.newDatabase(databaseName, key);
            return db !== undefined;
        });

        expect(result).to.equal(true);
    });

    it("can get the database location", async () => {
        const location = crypto.randomUUID();
        const result = await runOnPlatform(async (location) => {
            const db = await helpers.newDatabase(location);

            return await db.getLocation();
        }, location);

        expect(result).to.equal(location);
    });

    it("key must have correct length", async () => {
        const result = await runOnPlatform(async () => {
            try {
                new ccModule.DatabaseKey(new Uint8Array(11));
            } catch (err) {
                return ccModule.CoreCryptoError.Other.instanceOf(err);
            }
            throw new Error("Expected CoreCryptoError.Other");
        });
        expect(result).to.equal(true);
    });

    it("key update works", async () => {
        const [pubkey1, pubkey2] = await runOnPlatform(async () => {
            const key = helpers.newDatabaseKey();
            const database = await helpers.newDatabase(undefined, key);
            const clientId = helpers.newClientId();
            let cc = await helpers.ccInit({
                withBasicCredential: true,
                database,
                clientId,
            });

            const pubkey1 = (
                await cc.findCredentials({ clientId })
            )[0]!.publicKeyHash();

            const newKey = helpers.newDatabaseKey();

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

            return [JSON.stringify(pubkey1), JSON.stringify(pubkey2)];
        });

        expect(JSON.parse(pubkey1)).to.deep.equal(JSON.parse(pubkey2));
    });
});
