import { browser, expect } from "@wdio/globals";
import { setup, teardown } from "../../../shared/test/utils";
import { afterEach, beforeEach, describe } from "mocha";

beforeEach(async () => {
    await setup();
});

afterEach(async () => {
    await teardown();
});

describe("database", () => {
    it("throws an error if used after close", async () => {
        expect(
            await browser.execute(async () => {
                const databaseName = crypto.randomUUID();
                const key = new Uint8Array(32);

                const database = await ccModule.Database.open(
                    databaseName,
                    new ccModule.DatabaseKey(key)
                );

                await database.close();
                try {
                    await database.getLocation();
                    return false;
                } catch (e) {
                    return ccModule.CoreCryptoError.Other.instanceOf(e);
                }
            })
        ).toBe(true);
    });

    it("migrating key type to bytes works", async () => {
        const stores = await import("./db-v10002003-dump.json");

        // This fetch() and subsequent browser.executeScript() download and
        // inject the idb module into the browser context. We cannot do the
        // fetch from the browser context due to permissions so we first
        // download the code and then tell the browser to execute it. This also
        // means the TS compiler has no idea about it, which is why we use
        // ts-expect-error further down.
        const response = await fetch(
            "https://cdn.jsdelivr.net/npm/idb@8/build/umd.js"
        );
        if (!response.ok)
            throw new Error(`failed to fetch script: ${response.statusText}`);

        await browser.executeScript(await response.text(), []);

        const result = await browser.execute(async (stores_) => {
            // First, we need to restore the IndexedDB database in the browser.
            const stores: { string: [] } = JSON.parse(stores_);
            const clientName = "alice";
            const version = 10002003;
            // @ts-expect-error TS2304: Cannot find name 'idb'
            const db = await idb.openDB(clientName, version, {
                // @ts-expect-error TS7006: Parameter 'db' implicitly has an 'any' type
                async upgrade(db) {
                    for (const name of Object.keys(stores)) {
                        await db.createObjectStore(name);
                    }
                },
            });

            const chunks = (s: string) =>
                Array.from({ length: s.length / 2 }, (_, i) =>
                    s.substr(i * 2, 2)
                );
            const fromHex = (s: string) =>
                Uint8Array.from(chunks(s), (byte) => parseInt(byte, 16));

            for (const [name, value] of Object.entries(stores)) {
                for (const [key, val] of Object.entries(value)) {
                    await db.put(name, val, fromHex(key));
                }
            }

            // It is important to close the database here since otherwise the migration process
            // will be stuck because we'd be holding a connection to the same database open.
            db.close();

            // Migrate the whole database to use the new key type.
            const old_key = clientName;
            const new_key = new ccModule.DatabaseKey(new Uint8Array(32));
            await ccModule.migrateDatabaseKeyTypeToBytes(
                clientName,
                old_key,
                new_key
            );

            // Reconstruct the client based on the migrated database and fetch the epoch.
            const encoder = new TextEncoder();
            const database = await ccModule.Database.open(clientName, new_key);

            const instance = ccModule.CoreCrypto.new(database);
            const epoch = await instance.transaction(async (ctx) => {
                // note that `conversationEpoch` is a MLS operation so we must at some point initialize MLS
                const clientId = helpers.newClientId();
                await ctx.mlsInit(clientId, deliveryService);
                return await ctx.conversationEpoch(
                    new ccModule.ConversationId(encoder.encode("convId"))
                );
            });
            return epoch;
        }, JSON.stringify(stores));

        // If the migration succeeded, the epoch has to be 1.
        expect(result).toEqual(1n);
    });
});
